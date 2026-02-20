from __future__ import annotations

import asyncio
import os
import time
from typing import List

import anthropic

from ..core.models import AnomalyReport, Event, TrackerConfig
from ..engine import AnomalyTracker


async def run_simulation(
    tracker: AnomalyTracker,
    events: List[Event],
    inter_event_delay: float = 0.01,
) -> None:
    """
    Simulate a continuous event stream by pushing events into the tracker.
    In production replace this with a Kafka/Kinesis consumer.
    """
    for event in events:
        await tracker.ingest_event(event)
        await asyncio.sleep(inter_event_delay)


async def main() -> None:
    """End-to-end demo. Requires ANTHROPIC_API_KEY in the environment."""
    config = TrackerConfig(
        window_seconds=60,
        unique_endpoint_threshold=10,
        payload_threshold_bytes=10 * 1024 * 1024,
        micro_batch_seconds=10.0,
    )

    client = anthropic.AsyncAnthropic(api_key=os.environ["ANTHROPIC_API_KEY"])
    reports: List[AnomalyReport] = []

    async def on_report(report: AnomalyReport) -> None:
        reports.append(report)
        print(
            f"[ALERT] {report.context.source_ip} | "
            f"score={report.analysis.threat_score:.2f} | "
            f"rules={report.context.triggered_rules}"
        )
        print(f"  Mitigation: {report.analysis.suggested_mitigation}")
        for obs in report.analysis.observations:
            print(f"  - {obs}")

    tracker = AnomalyTracker(
        anthropic_client=client,
        config=config,
        report_callback=on_report,
    )

    now = time.time()
    events: List[Event] = []

    # Suspicious IP: hits 15 unique endpoints (threshold=10 → triggers)
    for i in range(15):
        events.append(
            Event(
                source_ip="192.168.1.100",
                endpoint=f"/api/resource/{i}",
                payload_size=500_000,
                timestamp=now + i * 2,
            )
        )

    # Benign IP: only hits 3 unique endpoints
    for i in range(5):
        events.append(
            Event(
                source_ip="10.0.0.50",
                endpoint="/api/health",
                payload_size=1_024,
                timestamp=now + i * 3,
            )
        )

    await tracker.start()
    try:
        await run_simulation(tracker, events, inter_event_delay=0.1)
        await asyncio.sleep(config.micro_batch_seconds + 1)
    finally:
        await tracker.stop()

    print(f"\nTotal anomaly reports generated: {len(reports)}")


def run_main() -> None:
    """Synchronous entry point for the console script."""
    asyncio.run(main())  # pragma: no cover - exercised by console script


if __name__ == "__main__":  # pragma: no cover
    run_main()
