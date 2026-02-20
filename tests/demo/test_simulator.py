"""Tests for the event stream simulator (anomaly_detection.demo.simulator)."""

from __future__ import annotations

import os
import time
from unittest.mock import patch

import pytest

from anomaly_detection.core.models import Event, TrackerConfig
from anomaly_detection.demo import run_simulation
from anomaly_detection.engine import AnomalyTracker
from ..conftest import make_mock_client, make_mock_local_analyser


@pytest.fixture
def tracker(config: TrackerConfig) -> AnomalyTracker:
    t = AnomalyTracker(config=config)
    t._llm = make_mock_local_analyser()
    return t


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


@pytest.mark.asyncio
async def test_main_runs_with_mocked_client():
    """Run main() in cloud mode with a mocked Anthropic client for coverage."""
    from anomaly_detection.demo.simulator import main

    with patch.dict(os.environ, {"ANTHROPIC_API_KEY": "test-key", "USE_CLOUD_LLM": "true"}):
        with patch(
            "anomaly_detection.demo.simulator.anthropic.AsyncAnthropic",
            return_value=make_mock_client(),
        ):
            await main()


