#!/usr/bin/env python3
"""
generate_test_data.py — scenario-based integration harness.

Drives AnomalyTracker directly via ingest_event() through three scenarios:

  Scenario 1 (Benign)        normal user, same endpoint, slow cadence.
                             Rules: silent. LLM: never called.

  Scenario 2 (Scanner)       1 IP hits 20 unique endpoints in 5 seconds.
                             Rules: fire. LLM: Reconnaissance.

  Scenario 3 (Exfiltration)  1 IP sends 50 MB to /api/export in one burst.
                             Rules: fire. LLM: Data Exfiltration.

Usage:
    python generate_test_data.py                     # local Ollama (default)
    USE_CLOUD_LLM=true python generate_test_data.py  # Anthropic Claude
    OLLAMA_MODEL=mistral python generate_test_data.py
"""
from __future__ import annotations

import asyncio
import os
import time
from typing import List, Optional

import anthropic

from anomaly_detection.core.models import AnomalyReport, Event, TrackerConfig
from anomaly_detection.engine import AnomalyTracker

# ── Settings ──────────────────────────────────────────────────────────────────

MICRO_BATCH_SECONDS = 2.0              # short flush interval for a fast demo
ENDPOINT_THRESHOLD  = 10               # default; benign hits 1, scanner hits 20
PAYLOAD_THRESHOLD   = 10 * 1024 * 1024 # 10 MB; exfil scenario sends 50 MB

_SEP = "─" * 67

# ── Internal helpers ──────────────────────────────────────────────────────────


def _build_tracker(
    config: TrackerConfig,
    anthropic_client: Optional[anthropic.AsyncAnthropic],
    reports: List[AnomalyReport],
) -> AnomalyTracker:
    """Construct a fresh tracker that appends every AnomalyReport to *reports*."""
    async def on_report(r: AnomalyReport) -> None:
        reports.append(r)

    return AnomalyTracker(
        config=config,
        report_callback=on_report,
        anthropic_client=anthropic_client,
    )


def _print_report(r: AnomalyReport) -> None:
    print(f"  Score       : {r.analysis.threat_score:.2f}")
    print(f"  Rules fired : {r.context.triggered_rules}")
    print(f"  Mitigation  : {r.analysis.suggested_mitigation}")
    for obs in r.analysis.observations:
        print(f"  Observation : {obs}")


# ── Scenario 1 — Benign ───────────────────────────────────────────────────────


async def scenario_benign(
    config: TrackerConfig,
    anthropic_client: Optional[anthropic.AsyncAnthropic],
) -> None:
    """
    Normal user hitting /api/profile once every 10 s.
    Expected: rules stay silent, LLM is never called.
    """
    print(f"\n┌─ Scenario 1: Benign {'─' * 46}┐")
    print("  Pattern  : same endpoint, 5 events, 10 s apart")
    print("  Expected : Rules silent — LLM never called")
    print()

    reports: List[AnomalyReport] = []
    tracker = _build_tracker(config, anthropic_client, reports)
    await tracker.start()

    now = time.time()
    for i in range(5):
        event = Event(
            source_ip="10.0.0.1",
            endpoint="/api/profile",   # one unique endpoint — threshold never reached
            payload_size=1_024,
            timestamp=now + i * 10,
        )
        print(f"  → {event.source_ip:<14}  {event.endpoint:<22}  {event.payload_size:>6} B")
        await tracker.ingest_event(event)

    await asyncio.sleep(MICRO_BATCH_SECONDS + 1)
    await tracker.stop()

    if reports:
        print(f"\n  [FAIL] Expected no alerts — received {len(reports)}")
    else:
        print(f"\n  [PASS] Rules: silent.  LLM: never called.")

    print(f"└{'─' * 67}┘")


# ── Scenario 2 — Scanner (Reconnaissance) ────────────────────────────────────


async def scenario_scanner(
    config: TrackerConfig,
    anthropic_client: Optional[anthropic.AsyncAnthropic],
) -> None:
    """
    1 IP probing 20 unique endpoints within 5 seconds.
    Expected: UNIQUE_ENDPOINT_THRESHOLD fires → LLM flags Reconnaissance.
    """
    print(f"\n┌─ Scenario 2: Scanner (Reconnaissance) {'─' * 28}┐")
    print(f"  Pattern  : 1 IP × 20 unique endpoints in 5 s")
    print(f"  Expected : UNIQUE_ENDPOINT_THRESHOLD → LLM: Reconnaissance")
    print()

    reports: List[AnomalyReport] = []
    tracker = _build_tracker(config, anthropic_client, reports)
    await tracker.start()

    now = time.time()
    for i in range(20):
        event = Event(
            source_ip="192.168.1.50",
            endpoint=f"/api/internal/resource/{i}",   # 20 unique endpoints
            payload_size=256,
            timestamp=now + i * 0.25,                  # spread over 5 s
        )
        print(f"  → {event.source_ip:<14}  {event.endpoint}")
        await tracker.ingest_event(event)

    print(f"\n  Waiting for LLM batch flush (~{MICRO_BATCH_SECONDS:.0f} s)…")
    await asyncio.sleep(MICRO_BATCH_SECONDS + 1)
    await tracker.stop()

    if reports:
        print(f"\n  [PASS] Alert received:")
        _print_report(reports[0])
    else:
        print("\n  [FAIL] Expected an alert — check endpoint threshold or LLM connectivity.")

    print(f"└{'─' * 67}┘")


# ── Scenario 3 — Exfiltration ─────────────────────────────────────────────────


async def scenario_exfiltration(
    config: TrackerConfig,
    anthropic_client: Optional[anthropic.AsyncAnthropic],
) -> None:
    """
    1 IP sending 50 MB to /api/export in a single event.
    Expected: PAYLOAD_THRESHOLD fires → LLM flags Data Exfiltration.
    """
    print(f"\n┌─ Scenario 3: Exfiltration {'─' * 40}┐")
    print("  Pattern  : 1 IP sends 50 MB to /api/export (single event)")
    print("  Expected : PAYLOAD_THRESHOLD → LLM: Data Exfiltration")
    print()

    reports: List[AnomalyReport] = []
    tracker = _build_tracker(config, anthropic_client, reports)
    await tracker.start()

    fifty_mb = 50 * 1024 * 1024
    event = Event(
        source_ip="172.16.0.99",
        endpoint="/api/export",
        payload_size=fifty_mb,
        timestamp=time.time(),
    )
    print(f"  → {event.source_ip:<14}  {event.endpoint:<22}  {event.payload_size // (1024 * 1024):>4} MB")
    await tracker.ingest_event(event)

    print(f"\n  Waiting for LLM batch flush (~{MICRO_BATCH_SECONDS:.0f} s)…")
    await asyncio.sleep(MICRO_BATCH_SECONDS + 1)
    await tracker.stop()

    if reports:
        print(f"\n  [PASS] Alert received:")
        _print_report(reports[0])
    else:
        print("\n  [FAIL] Expected an alert — check payload threshold or LLM connectivity.")

    print(f"└{'─' * 67}┘")


# ── Entry point ───────────────────────────────────────────────────────────────


async def main() -> None:
    use_cloud    = os.environ.get("USE_CLOUD_LLM", "false").lower() == "true"
    ollama_model = os.environ.get("OLLAMA_MODEL", "llama3")
    ollama_url   = os.environ.get("OLLAMA_BASE_URL", "http://localhost:11434")
    backend      = "Claude (cloud)" if use_cloud else f"Ollama/{ollama_model} (local)"

    config = TrackerConfig(
        window_seconds=60,
        unique_endpoint_threshold=ENDPOINT_THRESHOLD,
        payload_threshold_bytes=PAYLOAD_THRESHOLD,
        micro_batch_seconds=MICRO_BATCH_SECONDS,
        use_cloud_llm=use_cloud,
        ollama_model=ollama_model,
        ollama_base_url=ollama_url,
    )

    anthropic_client: Optional[anthropic.AsyncAnthropic] = None
    if use_cloud:
        anthropic_client = anthropic.AsyncAnthropic(api_key=os.environ["ANTHROPIC_API_KEY"])

    print("=" * 67)
    print("  Anomaly Detection — Test Data Generator")
    print("=" * 67)
    print(f"  LLM backend        : {backend}")
    print(f"  Endpoint threshold : > {ENDPOINT_THRESHOLD} unique endpoints / 60 s")
    print(f"  Payload threshold  : > {PAYLOAD_THRESHOLD // (1024 * 1024)} MB total")
    print(f"  Micro-batch flush  : every {MICRO_BATCH_SECONDS:.0f} s")
    print("=" * 67)

    await scenario_benign(config, anthropic_client)
    await scenario_scanner(config, anthropic_client)
    await scenario_exfiltration(config, anthropic_client)

    print(f"\n{'=' * 67}")
    print("  Done.")
    print("=" * 67)


if __name__ == "__main__":
    asyncio.run(main())
