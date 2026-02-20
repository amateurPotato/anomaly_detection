"""Tests for the symbolic rule engine (anomaly_detection.core.rules)."""

from __future__ import annotations

import time
from collections import deque

from anomaly_detection.core.rules import RuleEngine


# Fixture-like helper: engine with the same small thresholds as the test config
def make_engine(endpoint_threshold: int = 3, payload_threshold: int = 1000) -> RuleEngine:
    return RuleEngine(
        endpoint_threshold=endpoint_threshold,
        payload_threshold_bytes=payload_threshold,
    )


class TestRuleEngine:
    def test_below_both_thresholds_returns_none(self):
        engine = make_engine()
        now = time.time()
        window = deque([(now, "/a", 100), (now, "/b", 100)])
        assert engine.evaluate("1.2.3.4", window) is None

    def test_empty_window_returns_none(self):
        engine = make_engine()
        assert engine.evaluate("1.2.3.4", deque()) is None

    def test_unique_endpoint_rule_fires(self):
        engine = make_engine()
        now = time.time()
        # threshold=3 → 4 unique endpoints triggers
        window = deque([(now, f"/ep/{i}", 10) for i in range(4)])
        ctx = engine.evaluate("1.2.3.4", window)
        assert ctx is not None
        assert "UNIQUE_ENDPOINT_THRESHOLD" in ctx.triggered_rules

    def test_payload_rule_fires(self):
        engine = make_engine()
        now = time.time()
        window = deque([(now, "/same", 1001)])
        ctx = engine.evaluate("1.2.3.4", window)
        assert ctx is not None
        assert "PAYLOAD_THRESHOLD" in ctx.triggered_rules

    def test_both_rules_fire(self):
        engine = make_engine()
        now = time.time()
        # 4 unique * 300 bytes = 1200 > 1000
        window = deque([(now, f"/ep/{i}", 300) for i in range(4)])
        ctx = engine.evaluate("1.2.3.4", window)
        assert ctx is not None
        assert "UNIQUE_ENDPOINT_THRESHOLD" in ctx.triggered_rules
        assert "PAYLOAD_THRESHOLD" in ctx.triggered_rules

    def test_duplicate_visits_not_double_counted(self):
        engine = make_engine()
        now = time.time()
        window = deque([
            (now - 5, "/a", 100),
            (now - 3, "/b", 200),
            (now - 1, "/a", 150),  # duplicate — should still be 3 unique endpoints
            (now,     "/c", 600),  # total = 1050 > 1000
        ])
        ctx = engine.evaluate("1.2.3.4", window)
        assert ctx is not None
        assert set(ctx.unique_endpoints) == {"/a", "/b", "/c"}
        assert ctx.event_count == 4
        assert ctx.total_payload_size == 1050

    def test_window_timestamps_accurate(self):
        engine = make_engine()
        now = time.time()
        window = deque([
            (now - 10, "/a", 600),
            (now - 5,  "/b", 600),
        ])
        ctx = engine.evaluate("1.2.3.4", window)
        assert ctx is not None
        assert ctx.window_start == now - 10
        assert ctx.window_end == now - 5

    def test_ip_recorded_in_context(self):
        engine = make_engine()
        now = time.time()
        window = deque([(now, f"/ep/{i}", 10) for i in range(4)])
        ctx = engine.evaluate("10.0.0.1", window)
        assert ctx is not None
        assert ctx.source_ip == "10.0.0.1"
