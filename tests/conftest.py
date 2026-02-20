"""
Shared pytest fixtures used across the modular test suite.
"""

from __future__ import annotations

import time
from typing import List
from unittest.mock import AsyncMock, MagicMock

import pytest

from anomaly_detection.core.models import IPContext, LLMAnalysis, TrackerConfig


def make_mock_client(
    threat_score: float = 0.85,
    observations: List[str] | None = None,
    suggested_mitigation: str = "Block IP at firewall and alert SOC team",
) -> AsyncMock:
    """Return a mock AsyncAnthropic client whose messages.create returns a valid tool_use block."""
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


def make_mock_local_analyser(
    threat_score: float = 0.85,
    observations: List[str] | None = None,
    suggested_mitigation: str = "Block IP at firewall and alert SOC team",
) -> AsyncMock:
    """Return a mock LocalLLMAnalyser whose analyse() returns a valid LLMAnalysis."""
    if observations is None:
        observations = ["Accessed 11 unique endpoints in 60s", "High payload volume"]

    mock = AsyncMock()
    mock.analyse = AsyncMock(
        return_value=LLMAnalysis(
            threat_score=threat_score,
            observations=observations,
            suggested_mitigation=suggested_mitigation,
        )
    )
    return mock


def make_failing_local_analyser() -> AsyncMock:
    """Return a mock LocalLLMAnalyser whose analyse() always raises."""
    mock = AsyncMock()
    mock.analyse = AsyncMock(side_effect=Exception("LLM unavailable"))
    return mock


@pytest.fixture
def config() -> TrackerConfig:
    """Small thresholds so tests run fast."""
    return TrackerConfig(
        window_seconds=60,
        unique_endpoint_threshold=3,
        payload_threshold_bytes=1000,
        micro_batch_seconds=0.1,
        stale_window_seconds=300,
        circuit_breaker_threshold=3,
        circuit_breaker_cooldown_seconds=60.0,
    )


@pytest.fixture
def mock_client() -> AsyncMock:
    return make_mock_client()


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
