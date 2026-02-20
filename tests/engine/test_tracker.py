"""
Integration tests for AnomalyTracker (anomaly_detection.engine.tracker).

Tests the orchestrator end-to-end: event ingestion → rule evaluation →
micro-batch → circuit breaker → LLM → callback. Individual components
(RuleEngine, CircuitBreaker, LLMAnalyser) are tested in their own files.
"""

from __future__ import annotations

import asyncio
import time
from typing import List
from unittest.mock import AsyncMock

import pytest

from anomaly_detection.core.models import AnomalyReport, Event, TrackerConfig
from anomaly_detection.engine import AnomalyTracker
from ..conftest import make_failing_local_analyser, make_mock_local_analyser


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def make_tracker(
    config: TrackerConfig,
    mock_llm: AsyncMock | None = None,
    report_callback=None,
) -> AnomalyTracker:
    """Create an AnomalyTracker with a mock local LLM injected (no real HTTP calls)."""
    tracker = AnomalyTracker(config=config, report_callback=report_callback)
    tracker._llm = mock_llm if mock_llm is not None else make_mock_local_analyser()
    return tracker


# ---------------------------------------------------------------------------
# 1. Sliding window eviction
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
class TestSlidingWindowEviction:
    async def test_old_entries_evicted(self, config: TrackerConfig):
        tracker = make_tracker(config)
        now = time.time()
        old = Event(source_ip="10.0.0.1", endpoint="/old", payload_size=10, timestamp=now - 70)
        new = Event(source_ip="10.0.0.1", endpoint="/new", payload_size=10, timestamp=now)
        await tracker.ingest_event(old)
        await tracker.ingest_event(new)

        window = tracker._windows["10.0.0.1"]
        assert len(window) == 1
        assert window[0][1] == "/new"

    async def test_recent_entries_retained(self, config: TrackerConfig):
        tracker = make_tracker(config)
        now = time.time()
        for i in range(3):
            await tracker.ingest_event(
                Event(source_ip="10.0.0.2", endpoint=f"/ep/{i}", payload_size=10,
                      timestamp=now - i * 10)
            )
        assert len(tracker._windows["10.0.0.2"]) == 3

    async def test_new_ip_starts_empty(self, config: TrackerConfig):
        tracker = make_tracker(config)
        assert "172.16.0.1" not in tracker._windows


# ---------------------------------------------------------------------------
# 2. Micro-batch deduplication
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
class TestMicroBatchDeduplication:
    async def test_same_ip_replaced_in_pending(self, config: TrackerConfig):
        tracker = make_tracker(config)
        now = time.time()
        for i in range(4):   # first breach
            await tracker.ingest_event(
                Event(source_ip="5.5.5.5", endpoint=f"/first/{i}", payload_size=50,
                      timestamp=now + i)
            )
        await tracker.ingest_event(
            Event(source_ip="5.5.5.5", endpoint="/second/new", payload_size=50,
                  timestamp=now + 10)
        )

        async with tracker._batch_lock:
            pending = [c for c in tracker._pending_contexts if c.source_ip == "5.5.5.5"]

        assert len(pending) == 1
        assert any("/second/new" in ep for ep in pending[0].unique_endpoints)


# ---------------------------------------------------------------------------
# 3. Stale window cleanup
# ---------------------------------------------------------------------------


class TestCleanupStaleWindows:
    def test_stale_ip_removed(self, config: TrackerConfig):
        tracker = make_tracker(config)
        old_ts = time.time() - (config.stale_window_seconds + 10)
        tracker._windows["1.2.3.4"].append((old_ts, "/old", 100))
        tracker._cleanup_stale_windows()
        assert "1.2.3.4" not in tracker._windows

    def test_active_ip_retained(self, config: TrackerConfig):
        tracker = make_tracker(config)
        tracker._windows["5.6.7.8"].append((time.time() - 10, "/recent", 100))
        tracker._cleanup_stale_windows()
        assert "5.6.7.8" in tracker._windows

    def test_empty_window_removed(self, config: TrackerConfig):
        tracker = make_tracker(config)
        _ = tracker._windows["9.9.9.9"]   # creates empty deque via defaultdict
        tracker._cleanup_stale_windows()
        assert "9.9.9.9" not in tracker._windows

    def test_mixed_ips_only_stale_removed(self, config: TrackerConfig):
        tracker = make_tracker(config)
        now = time.time()
        tracker._windows["stale.ip"].append((now - (config.stale_window_seconds + 1), "/x", 10))
        tracker._windows["active.ip"].append((now - 5, "/y", 10))
        tracker._cleanup_stale_windows()
        assert "stale.ip" not in tracker._windows
        assert "active.ip" in tracker._windows


@pytest.mark.asyncio
class TestCleanupStaleWindowsIntegration:
    async def test_cleanup_called_by_flush_loop(self):
        cfg = TrackerConfig(micro_batch_seconds=0.1, stale_window_seconds=0)
        tracker = make_tracker(cfg)
        tracker._windows["2.2.2.2"].append((time.time() - 1, "/gone", 10))

        await tracker.start()
        await asyncio.sleep(0.25)
        await tracker.stop()

        assert "2.2.2.2" not in tracker._windows


# ---------------------------------------------------------------------------
# 4. Circuit breaker integration (via _analyze_and_emit)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
class TestCircuitBreakerIntegration:
    async def test_failure_increments_circuit_breaker(
        self, config: TrackerConfig, sample_context
    ):
        tracker = make_tracker(config, mock_llm=make_failing_local_analyser())
        await tracker._analyze_and_emit(sample_context, "batch-1")
        assert tracker._circuit_breaker.consecutive_failures == 1

    async def test_success_resets_circuit_breaker(
        self, config: TrackerConfig, sample_context
    ):
        tracker = make_tracker(config)
        tracker._circuit_breaker._consecutive_failures = 2
        await tracker._analyze_and_emit(sample_context, "batch-1")
        assert tracker._circuit_breaker.consecutive_failures == 0

    async def test_circuit_opens_after_threshold(self, config: TrackerConfig, sample_context):
        tracker = make_tracker(config, mock_llm=make_failing_local_analyser())
        for i in range(config.circuit_breaker_threshold):
            await tracker._analyze_and_emit(sample_context, f"b-{i}")
        assert tracker._circuit_breaker.open_at is not None

    async def test_open_circuit_skips_llm(self, config: TrackerConfig, sample_context):
        mock_llm = make_failing_local_analyser()
        tracker = make_tracker(config, mock_llm=mock_llm)
        tracker._circuit_breaker._open_at = time.time()
        tracker._circuit_breaker._consecutive_failures = config.circuit_breaker_threshold
        await tracker._analyze_and_emit(sample_context, "skip")
        mock_llm.analyse.assert_not_called()

    async def test_symbolic_rules_fire_while_circuit_open(
        self, config: TrackerConfig
    ):
        tracker = make_tracker(config, mock_llm=make_failing_local_analyser())
        tracker._circuit_breaker._open_at = time.time()
        tracker._circuit_breaker._consecutive_failures = config.circuit_breaker_threshold

        now = time.time()
        for i in range(4):
            await tracker.ingest_event(
                Event(source_ip="9.9.9.9", endpoint=f"/ep/{i}",
                      payload_size=50, timestamp=now + i)
            )

        async with tracker._batch_lock:
            pending = [c for c in tracker._pending_contexts if c.source_ip == "9.9.9.9"]
        assert len(pending) == 1


# ---------------------------------------------------------------------------
# 5. Full lifecycle
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
class TestLifecycle:
    async def test_stop_without_start_is_safe(self, config: TrackerConfig):
        """stop() without start() does not raise; _flush_task is None."""
        tracker = make_tracker(config)
        await tracker.stop()
        assert tracker._running is False
        assert tracker._flush_task is None

    async def test_start_and_stop(self, config: TrackerConfig):
        tracker = make_tracker(config)
        await tracker.start()
        assert tracker._running is True
        assert tracker._flush_task is not None
        await tracker.stop()
        assert tracker._running is False

    async def test_report_callback_invoked_on_alert(self, config: TrackerConfig):
        received: List[AnomalyReport] = []

        async def on_report(r: AnomalyReport) -> None:
            received.append(r)

        tracker = make_tracker(config, report_callback=on_report)
        await tracker.start()
        now = time.time()
        for i in range(4):   # 4 unique endpoints > threshold of 3
            await tracker.ingest_event(
                Event(source_ip="192.168.100.1", endpoint=f"/scan/{i}",
                      payload_size=50, timestamp=now + i)
            )
        await asyncio.sleep(0.3)
        await tracker.stop()

        assert len(received) == 1
        assert received[0].context.source_ip == "192.168.100.1"
        assert received[0].analysis.threat_score == 0.85

    async def test_benign_ip_no_callback(self, config: TrackerConfig):
        received: List[AnomalyReport] = []

        async def on_report(r: AnomalyReport) -> None:
            received.append(r)

        tracker = make_tracker(config, report_callback=on_report)
        await tracker.start()
        now = time.time()
        for _ in range(5):
            await tracker.ingest_event(
                Event(source_ip="10.0.0.1", endpoint="/health",
                      payload_size=10, timestamp=now)
            )
        await asyncio.sleep(0.3)
        await tracker.stop()
        assert received == []

    async def test_llm_error_does_not_crash_engine(self, config: TrackerConfig):
        tracker = make_tracker(config, mock_llm=make_failing_local_analyser())
        await tracker.start()
        now = time.time()
        for i in range(4):
            await tracker.ingest_event(
                Event(source_ip="1.2.3.4", endpoint=f"/ep/{i}",
                      payload_size=300, timestamp=now + i)
            )
        await asyncio.sleep(0.3)
        await tracker.stop()   # must not raise

    async def test_stop_flushes_remaining_batch(self, config: TrackerConfig):
        received: List[AnomalyReport] = []

        async def on_report(r: AnomalyReport) -> None:
            received.append(r)

        tracker = make_tracker(config, report_callback=on_report)
        await tracker.start()
        now = time.time()
        for i in range(4):
            await tracker.ingest_event(
                Event(source_ip="7.7.7.7", endpoint=f"/ep/{i}",
                      payload_size=50, timestamp=now + i)
            )
        await tracker.stop()   # immediate stop triggers final flush
        assert len(received) == 1

    async def test_no_callback_registered(self, config: TrackerConfig):
        tracker = make_tracker(config)
        await tracker.start()
        now = time.time()
        for i in range(4):
            await tracker.ingest_event(
                Event(source_ip="3.3.3.3", endpoint=f"/ep/{i}",
                      payload_size=50, timestamp=now + i)
            )
        await asyncio.sleep(0.3)
        await tracker.stop()

    async def test_flush_loop_exits_when_running_false(self, config: TrackerConfig):
        """When report_callback sets _running=False, _flush_loop exits (covers while exit branch)."""
        received: List[AnomalyReport] = []

        async def on_report(r: AnomalyReport) -> None:
            received.append(r)
            tracker._running = False

        tracker = make_tracker(config, report_callback=on_report)
        await tracker.start()
        now = time.time()
        for i in range(4):
            await tracker.ingest_event(
                Event(source_ip="8.8.8.8", endpoint=f"/ep/{i}",
                      payload_size=50, timestamp=now + i)
            )
        await asyncio.sleep(0.5)
        assert len(received) == 1
        assert tracker._running is False
        await tracker.stop()
