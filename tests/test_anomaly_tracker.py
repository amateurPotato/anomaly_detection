"""
Test suite for the Security Anomaly Engine.

Coverage strategy
-----------------
- Unit tests for each method in isolation (rule logic, prompt building).
- Integration tests for the full async flow (ingest → rule → batch → LLM → report).
- All branches in _evaluate_rules, ingest_event, flush, and analyze_with_llm are covered.
- The Anthropic client is fully replaced by AsyncMock — no real API calls.
"""

from __future__ import annotations

import asyncio
import time
from collections import deque
from typing import List
from unittest.mock import AsyncMock, MagicMock

import pytest
from pydantic import ValidationError

from src.anomaly_tracker import ANALYSIS_TOOL_SCHEMA, AnomalyTracker, run_simulation
from src.models import AnomalyReport, Event, IPContext, LLMAnalysis, TrackerConfig


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def config() -> TrackerConfig:
    """Small thresholds so tests trigger quickly."""
    return TrackerConfig(
        window_seconds=60,
        unique_endpoint_threshold=3,   # fires when > 3 unique endpoints
        payload_threshold_bytes=1000,  # fires when total payload > 1000 bytes
        micro_batch_seconds=0.1,
    )


def make_mock_client(
    threat_score: float = 0.85,
    observations: List[str] = None,
    suggested_mitigation: str = "Block IP at firewall and alert SOC team",
) -> AsyncMock:
    """Build a mock AsyncAnthropic client returning a valid tool_use response."""
    if observations is None:
        observations = ["Accessed 11 unique endpoints in 60s", "High payload volume"]

    tool_block = MagicMock()
    tool_block.type = "tool_use"
    tool_block.input = {
        "threat_score": threat_score,
        "observations": observations,
        "suggested_mitigation": suggested_mitigation,
    }

    response = MagicMock()
    response.content = [tool_block]
    response.stop_reason = "tool_use"

    client = AsyncMock()
    client.messages.create = AsyncMock(return_value=response)
    return client


@pytest.fixture
def mock_client() -> AsyncMock:
    return make_mock_client()


@pytest.fixture
def tracker(config: TrackerConfig, mock_client: AsyncMock) -> AnomalyTracker:
    return AnomalyTracker(anthropic_client=mock_client, config=config)


@pytest.fixture
def sample_context() -> IPContext:
    now = time.time()
    return IPContext(
        source_ip="192.168.1.1",
        unique_endpoints=[f"/api/{i}" for i in range(5)],
        total_payload_size=5000,
        event_count=10,
        window_start=now - 30,
        window_end=now,
        triggered_rules=["UNIQUE_ENDPOINT_THRESHOLD"],
    )


# ---------------------------------------------------------------------------
# 1. Model validation
# ---------------------------------------------------------------------------


class TestEventModel:
    def test_valid_event(self):
        e = Event(source_ip="1.2.3.4", endpoint="/api/data", payload_size=100)
        assert e.payload_size == 100

    def test_default_timestamp_is_recent(self):
        before = time.time()
        e = Event(source_ip="1.2.3.4", endpoint="/x", payload_size=0)
        assert before <= e.timestamp <= time.time()

    def test_custom_timestamp_preserved(self):
        ts = 1_700_000_000.0
        e = Event(source_ip="1.2.3.4", endpoint="/x", payload_size=0, timestamp=ts)
        assert e.timestamp == ts

    def test_negative_payload_raises(self):
        with pytest.raises(ValidationError):
            Event(source_ip="1.2.3.4", endpoint="/x", payload_size=-1)

    def test_invalid_ip_raises(self):
        with pytest.raises(ValidationError):
            Event(source_ip="not-an-ip", endpoint="/x", payload_size=0)

    def test_empty_endpoint_raises(self):
        with pytest.raises(ValidationError):
            Event(source_ip="1.2.3.4", endpoint="   ", payload_size=0)


class TestLLMAnalysis:
    def test_valid_analysis(self):
        a = LLMAnalysis(
            threat_score=0.5, observations=["obs"], suggested_mitigation="block"
        )
        assert a.threat_score == 0.5

    def test_threat_score_below_zero_raises(self):
        with pytest.raises(ValidationError):
            LLMAnalysis(threat_score=-0.1, observations=["x"], suggested_mitigation="y")

    def test_threat_score_above_one_raises(self):
        with pytest.raises(ValidationError):
            LLMAnalysis(threat_score=1.1, observations=["x"], suggested_mitigation="y")

    def test_empty_observations_raises(self):
        with pytest.raises(ValidationError):
            LLMAnalysis(threat_score=0.5, observations=[], suggested_mitigation="block")

    def test_empty_mitigation_raises(self):
        with pytest.raises(ValidationError):
            LLMAnalysis(threat_score=0.5, observations=["x"], suggested_mitigation="")


class TestTrackerConfig:
    def test_defaults(self):
        cfg = TrackerConfig()
        assert cfg.window_seconds == 60
        assert cfg.unique_endpoint_threshold == 10
        assert cfg.micro_batch_seconds == 10.0

    def test_override(self):
        cfg = TrackerConfig(unique_endpoint_threshold=5)
        assert cfg.unique_endpoint_threshold == 5


# ---------------------------------------------------------------------------
# 2. Rule engine (_evaluate_rules)
# ---------------------------------------------------------------------------


class TestEvaluateRules:
    def test_below_both_thresholds_returns_none(self, tracker: AnomalyTracker):
        now = time.time()
        # 2 unique endpoints, 200 bytes — both below threshold
        window = deque([(now, "/a", 100), (now, "/b", 100)])
        assert tracker._evaluate_rules("1.2.3.4", window) is None

    def test_empty_window_returns_none(self, tracker: AnomalyTracker):
        assert tracker._evaluate_rules("1.2.3.4", deque()) is None

    def test_unique_endpoint_rule_fires(self, tracker: AnomalyTracker):
        now = time.time()
        # threshold=3, so 4 unique endpoints triggers
        window = deque([(now, f"/ep/{i}", 10) for i in range(4)])
        ctx = tracker._evaluate_rules("1.2.3.4", window)
        assert ctx is not None
        assert "UNIQUE_ENDPOINT_THRESHOLD" in ctx.triggered_rules

    def test_payload_rule_fires(self, tracker: AnomalyTracker):
        now = time.time()
        # 1 unique endpoint, payload=1001 > 1000
        window = deque([(now, "/same", 1001)])
        ctx = tracker._evaluate_rules("1.2.3.4", window)
        assert ctx is not None
        assert "PAYLOAD_THRESHOLD" in ctx.triggered_rules

    def test_both_rules_fire(self, tracker: AnomalyTracker):
        now = time.time()
        # 4 unique * 300 bytes each = 1200 > 1000
        window = deque([(now, f"/ep/{i}", 300) for i in range(4)])
        ctx = tracker._evaluate_rules("1.2.3.4", window)
        assert ctx is not None
        assert "UNIQUE_ENDPOINT_THRESHOLD" in ctx.triggered_rules
        assert "PAYLOAD_THRESHOLD" in ctx.triggered_rules

    def test_duplicate_visits_not_double_counted(self, tracker: AnomalyTracker):
        now = time.time()
        # /a visited twice — unique_endpoints should be {/a, /b, /c} = 3, not 4
        window = deque([
            (now - 5, "/a", 100),
            (now - 3, "/b", 200),
            (now - 1, "/a", 150),  # duplicate
            (now,     "/c", 600),  # total = 1050 > 1000
        ])
        ctx = tracker._evaluate_rules("1.2.3.4", window)
        assert ctx is not None
        assert set(ctx.unique_endpoints) == {"/a", "/b", "/c"}
        assert ctx.event_count == 4
        assert ctx.total_payload_size == 1050

    def test_window_timestamps_correct(self, tracker: AnomalyTracker):
        now = time.time()
        window = deque([
            (now - 10, "/a", 600),
            (now - 5,  "/b", 600),
        ])
        ctx = tracker._evaluate_rules("1.2.3.4", window)
        assert ctx is not None
        assert ctx.window_start == now - 10
        assert ctx.window_end == now - 5


# ---------------------------------------------------------------------------
# 3. Sliding window eviction (via ingest_event)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
class TestSlidingWindowEviction:
    async def test_old_entries_evicted(self, tracker: AnomalyTracker):
        now = time.time()
        old = Event(source_ip="10.0.0.1", endpoint="/old", payload_size=100, timestamp=now - 70)
        new = Event(source_ip="10.0.0.1", endpoint="/new", payload_size=100, timestamp=now)
        await tracker.ingest_event(old)
        await tracker.ingest_event(new)

        window = tracker._windows["10.0.0.1"]
        assert len(window) == 1
        assert window[0][1] == "/new"

    async def test_recent_entries_retained(self, tracker: AnomalyTracker):
        now = time.time()
        for i in range(3):
            await tracker.ingest_event(
                Event(source_ip="10.0.0.2", endpoint=f"/ep/{i}", payload_size=50,
                      timestamp=now - i * 10)
            )
        assert len(tracker._windows["10.0.0.2"]) == 3

    async def test_new_ip_starts_empty(self, tracker: AnomalyTracker):
        assert "172.16.0.1" not in tracker._windows


# ---------------------------------------------------------------------------
# 4. Micro-batch deduplication
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
class TestMicroBatchDeduplication:
    async def test_same_ip_replaced_in_pending(self, tracker: AnomalyTracker):
        """Two threshold breaches for the same IP before flush → only latest kept."""
        now = time.time()
        for i in range(4):  # first breach: 4 unique endpoints
            await tracker.ingest_event(
                Event(source_ip="5.5.5.5", endpoint=f"/first/{i}", payload_size=50,
                      timestamp=now + i)
            )
        # second breach: adds a new endpoint
        await tracker.ingest_event(
            Event(source_ip="5.5.5.5", endpoint="/second/new", payload_size=50,
                  timestamp=now + 10)
        )

        async with tracker._batch_lock:
            pending = [c for c in tracker._pending_contexts if c.source_ip == "5.5.5.5"]

        assert len(pending) == 1
        assert any("/second/new" in ep for ep in pending[0].unique_endpoints)


# ---------------------------------------------------------------------------
# 5. analyze_with_llm
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
class TestAnalyzeWithLLM:
    async def test_returns_valid_llm_analysis(
        self, tracker: AnomalyTracker, sample_context: IPContext
    ):
        result = await tracker.analyze_with_llm(sample_context)
        assert isinstance(result, LLMAnalysis)
        assert result.threat_score == 0.85
        assert len(result.observations) == 2

    async def test_correct_api_call_parameters(
        self, tracker: AnomalyTracker, sample_context: IPContext, mock_client: AsyncMock
    ):
        await tracker.analyze_with_llm(sample_context)
        kwargs = mock_client.messages.create.call_args.kwargs
        assert kwargs["model"] == "claude-opus-4-6"
        assert kwargs["tools"] == [ANALYSIS_TOOL_SCHEMA]
        assert kwargs["tool_choice"] == {"type": "tool", "name": "report_anomaly_analysis"}

    async def test_raises_when_no_tool_use_block(
        self, tracker: AnomalyTracker, sample_context: IPContext, mock_client: AsyncMock
    ):
        text_block = MagicMock()
        text_block.type = "text"
        mock_client.messages.create.return_value.content = [text_block]

        with pytest.raises(ValueError, match="tool_use block"):
            await tracker.analyze_with_llm(sample_context)

    async def test_raises_on_invalid_schema(
        self, tracker: AnomalyTracker, sample_context: IPContext, mock_client: AsyncMock
    ):
        bad_block = MagicMock()
        bad_block.type = "tool_use"
        bad_block.input = {"threat_score": 9.9, "observations": ["x"], "suggested_mitigation": "y"}
        mock_client.messages.create.return_value.content = [bad_block]

        with pytest.raises(ValidationError):
            await tracker.analyze_with_llm(sample_context)


# ---------------------------------------------------------------------------
# 6. _build_prompt
# ---------------------------------------------------------------------------


class TestBuildPrompt:
    def test_prompt_contains_ip_and_rules(
        self, tracker: AnomalyTracker, sample_context: IPContext
    ):
        prompt = tracker._build_prompt(sample_context)
        assert sample_context.source_ip in prompt
        assert "UNIQUE_ENDPOINT_THRESHOLD" in prompt
        assert f"{sample_context.total_payload_size:,}" in prompt

    def test_prompt_truncates_endpoint_list_over_20(self, tracker: AnomalyTracker):
        ctx = IPContext(
            source_ip="1.2.3.4",
            unique_endpoints=[f"/ep/{i}" for i in range(25)],
            total_payload_size=5000,
            event_count=25,
            window_start=time.time() - 30,
            window_end=time.time(),
            triggered_rules=["UNIQUE_ENDPOINT_THRESHOLD"],
        )
        prompt = tracker._build_prompt(ctx)
        assert "truncated" in prompt

    def test_prompt_no_truncation_under_20(self, tracker: AnomalyTracker):
        ctx = IPContext(
            source_ip="1.2.3.4",
            unique_endpoints=[f"/ep/{i}" for i in range(10)],
            total_payload_size=5000,
            event_count=10,
            window_start=time.time() - 30,
            window_end=time.time(),
            triggered_rules=["UNIQUE_ENDPOINT_THRESHOLD"],
        )
        prompt = tracker._build_prompt(ctx)
        assert "truncated" not in prompt

    def test_prompt_contains_lateral_movement_tip(
        self, tracker: AnomalyTracker, sample_context: IPContext
    ):
        prompt = tracker._build_prompt(sample_context)
        assert "Lateral Movement" in prompt


# ---------------------------------------------------------------------------
# 7. Full lifecycle / integration tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
class TestLifecycle:
    async def test_start_and_stop(self, tracker: AnomalyTracker):
        await tracker.start()
        assert tracker._running is True
        assert tracker._flush_task is not None
        await tracker.stop()
        assert tracker._running is False

    async def test_report_callback_invoked_on_alert(self, config: TrackerConfig):
        received: List[AnomalyReport] = []

        async def on_report(r: AnomalyReport) -> None:
            received.append(r)

        tracker = AnomalyTracker(
            anthropic_client=make_mock_client(),
            config=config,
            report_callback=on_report,
        )
        await tracker.start()
        now = time.time()

        # 4 unique endpoints > threshold of 3
        for i in range(4):
            await tracker.ingest_event(
                Event(source_ip="192.168.100.1", endpoint=f"/scan/{i}",
                      payload_size=50, timestamp=now + i)
            )

        await asyncio.sleep(0.3)   # let micro-batch (0.1s) fire
        await tracker.stop()

        assert len(received) == 1
        assert received[0].context.source_ip == "192.168.100.1"
        assert received[0].analysis.threat_score == 0.85

    async def test_benign_ip_no_callback(self, config: TrackerConfig):
        received: List[AnomalyReport] = []

        async def on_report(r: AnomalyReport) -> None:
            received.append(r)

        tracker = AnomalyTracker(
            anthropic_client=make_mock_client(),
            config=config,
            report_callback=on_report,
        )
        await tracker.start()
        now = time.time()

        # Only hits /health — same endpoint, never breaches unique threshold
        for _ in range(5):
            await tracker.ingest_event(
                Event(source_ip="10.0.0.1", endpoint="/health",
                      payload_size=10, timestamp=now)
            )

        await asyncio.sleep(0.3)
        await tracker.stop()
        assert received == []

    async def test_llm_error_does_not_crash_engine(self, config: TrackerConfig):
        failing_client = AsyncMock()
        failing_client.messages.create = AsyncMock(side_effect=Exception("Network timeout"))

        tracker = AnomalyTracker(anthropic_client=failing_client, config=config)
        await tracker.start()
        now = time.time()

        for i in range(4):
            await tracker.ingest_event(
                Event(source_ip="1.2.3.4", endpoint=f"/ep/{i}",
                      payload_size=300, timestamp=now + i)
            )

        # Must not raise even though LLM always fails
        await asyncio.sleep(0.3)
        await tracker.stop()

    async def test_stop_flushes_remaining_batch(self, config: TrackerConfig):
        received: List[AnomalyReport] = []

        async def on_report(r: AnomalyReport) -> None:
            received.append(r)

        tracker = AnomalyTracker(
            anthropic_client=make_mock_client(),
            config=config,
            report_callback=on_report,
        )
        await tracker.start()
        now = time.time()

        for i in range(4):
            await tracker.ingest_event(
                Event(source_ip="7.7.7.7", endpoint=f"/ep/{i}",
                      payload_size=50, timestamp=now + i)
            )

        # Stop immediately — final flush must still process the pending context
        await tracker.stop()
        assert len(received) == 1

    async def test_no_callback_registered(self, config: TrackerConfig):
        """Engine runs without a callback — should complete without error."""
        tracker = AnomalyTracker(anthropic_client=make_mock_client(), config=config)
        await tracker.start()
        now = time.time()

        for i in range(4):
            await tracker.ingest_event(
                Event(source_ip="3.3.3.3", endpoint=f"/ep/{i}",
                      payload_size=50, timestamp=now + i)
            )

        await asyncio.sleep(0.3)
        await tracker.stop()


# ---------------------------------------------------------------------------
# 8. run_simulation
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
class TestRunSimulation:
    async def test_all_events_ingested(self, tracker: AnomalyTracker):
        now = time.time()
        events = [
            Event(source_ip="1.1.1.1", endpoint=f"/ep/{i}",
                  payload_size=10, timestamp=now + i)
            for i in range(3)
        ]
        await run_simulation(tracker, events, inter_event_delay=0.0)
        assert len(tracker._windows["1.1.1.1"]) == 3

    async def test_empty_event_list(self, tracker: AnomalyTracker):
        await run_simulation(tracker, [], inter_event_delay=0.0)
        assert tracker._windows == {}
