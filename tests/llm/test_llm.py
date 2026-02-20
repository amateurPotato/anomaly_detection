"""Tests for the LLM analysis layer (anomaly_detection.llm.analyser)."""

from __future__ import annotations

import time
from unittest.mock import AsyncMock, MagicMock

import pytest
from pydantic import ValidationError

from anomaly_detection.core.models import IPContext
from anomaly_detection.llm import ANALYSIS_TOOL_SCHEMA, LLMAnalyser


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


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


def make_analyser(
    threat_score: float = 0.85,
    observations: list | None = None,
    suggested_mitigation: str = "Block IP at firewall and alert SOC team",
) -> tuple[LLMAnalyser, AsyncMock]:
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

    mock_client = AsyncMock()
    mock_client.messages.create = AsyncMock(return_value=response)

    analyser = LLMAnalyser(client=mock_client)
    return analyser, mock_client


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
class TestLLMAnalyser:
    async def test_returns_valid_llm_analysis(self, sample_context: IPContext):
        analyser, _ = make_analyser()
        result = await analyser.analyse(sample_context)
        assert result.threat_score == 0.85
        assert len(result.observations) == 2
        assert "Block IP" in result.suggested_mitigation

    async def test_correct_model_and_tool_choice(self, sample_context: IPContext):
        analyser, mock_client = make_analyser()
        await analyser.analyse(sample_context)
        kwargs = mock_client.messages.create.call_args.kwargs
        assert kwargs["model"] == LLMAnalyser.DEFAULT_MODEL
        assert kwargs["tools"] == [ANALYSIS_TOOL_SCHEMA]
        assert kwargs["tool_choice"] == {"type": "tool", "name": "report_anomaly_analysis"}

    async def test_raises_when_no_tool_use_block(self, sample_context: IPContext):
        analyser, mock_client = make_analyser()
        text_block = MagicMock()
        text_block.type = "text"
        mock_client.messages.create.return_value.content = [text_block]
        with pytest.raises(ValueError, match="tool_use block"):
            await analyser.analyse(sample_context)

    async def test_raises_on_invalid_schema(self, sample_context: IPContext):
        analyser, mock_client = make_analyser()
        bad_block = MagicMock()
        bad_block.type = "tool_use"
        bad_block.input = {"threat_score": 9.9, "observations": ["x"], "suggested_mitigation": "y"}
        mock_client.messages.create.return_value.content = [bad_block]
        with pytest.raises(ValidationError):
            await analyser.analyse(sample_context)


class TestBuildPrompt:
    def test_contains_ip_and_rules(self, sample_context: IPContext):
        analyser, _ = make_analyser()
        prompt = analyser.build_prompt(sample_context)
        assert sample_context.source_ip in prompt
        assert "UNIQUE_ENDPOINT_THRESHOLD" in prompt
        assert f"{sample_context.total_payload_size:,}" in prompt

    def test_truncates_endpoint_list_over_20(self):
        analyser, _ = make_analyser()
        ctx = IPContext(
            source_ip="1.2.3.4",
            unique_endpoints=[f"/ep/{i}" for i in range(25)],
            total_payload_size=5000,
            event_count=25,
            window_start=time.time() - 30,
            window_end=time.time(),
            triggered_rules=["UNIQUE_ENDPOINT_THRESHOLD"],
        )
        assert "truncated" in analyser.build_prompt(ctx)

    def test_no_truncation_under_20(self):
        analyser, _ = make_analyser()
        ctx = IPContext(
            source_ip="1.2.3.4",
            unique_endpoints=[f"/ep/{i}" for i in range(10)],
            total_payload_size=5000,
            event_count=10,
            window_start=time.time() - 30,
            window_end=time.time(),
            triggered_rules=["UNIQUE_ENDPOINT_THRESHOLD"],
        )
        assert "truncated" not in analyser.build_prompt(ctx)

    def test_contains_lateral_movement_tip(self, sample_context: IPContext):
        analyser, _ = make_analyser()
        assert "Lateral Movement" in analyser.build_prompt(sample_context)
