"""Tests for all Pydantic models in anomaly_detection.core.models."""

from __future__ import annotations

import time

import pytest
from pydantic import ValidationError

from anomaly_detection.core.models import Event, LLMAnalysis, TrackerConfig


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
        assert cfg.stale_window_seconds == 300
        assert cfg.circuit_breaker_threshold == 5
        assert cfg.circuit_breaker_cooldown_seconds == 60.0

    def test_override(self):
        cfg = TrackerConfig(
            unique_endpoint_threshold=5,
            stale_window_seconds=60,
            circuit_breaker_threshold=3,
            circuit_breaker_cooldown_seconds=30.0,
        )
        assert cfg.unique_endpoint_threshold == 5
        assert cfg.stale_window_seconds == 60
        assert cfg.circuit_breaker_threshold == 3
        assert cfg.circuit_breaker_cooldown_seconds == 30.0
