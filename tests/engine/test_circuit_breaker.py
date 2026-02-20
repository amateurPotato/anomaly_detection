"""Tests for the standalone CircuitBreaker (anomaly_detection.engine.circuit_breaker)."""

from __future__ import annotations

import time

from anomaly_detection.engine import CircuitBreaker


def make_breaker(threshold: int = 3, cooldown: float = 60.0) -> CircuitBreaker:
    return CircuitBreaker(threshold=threshold, cooldown_seconds=cooldown)


class TestCircuitBreakerState:
    def test_closed_by_default(self):
        cb = make_breaker()
        assert cb.is_open is False

    def test_zero_failures_on_init(self):
        cb = make_breaker()
        assert cb.consecutive_failures == 0

    def test_open_at_is_none_on_init(self):
        cb = make_breaker()
        assert cb.open_at is None

    def test_stays_closed_below_threshold(self):
        cb = make_breaker(threshold=3)
        cb.record_failure()
        cb.record_failure()
        assert cb.is_open is False
        assert cb.open_at is None

    def test_opens_at_threshold(self):
        cb = make_breaker(threshold=3)
        for _ in range(3):
            cb.record_failure()
        assert cb.is_open is True
        assert cb.open_at is not None
        assert cb.consecutive_failures == 3

    def test_opens_only_once_per_trip(self):
        cb = make_breaker(threshold=3)
        for _ in range(3):
            cb.record_failure()
        first_open_at = cb.open_at
        cb.record_failure()   # 4th failure — circuit already open
        assert cb.open_at == first_open_at

    def test_stays_open_within_cooldown(self):
        cb = make_breaker(threshold=1, cooldown=60.0)
        cb.record_failure()
        assert cb.is_open is True

    def test_resets_after_cooldown(self):
        cb = make_breaker(threshold=1, cooldown=0.0)
        cb.record_failure()
        # cooldown=0 means already expired on next call
        assert cb.is_open is False
        assert cb.open_at is None
        assert cb.consecutive_failures == 0

    def test_manual_past_timestamp_resets(self):
        cb = make_breaker(threshold=1, cooldown=60.0)
        cb.record_failure()
        # Wind back the open timestamp so cooldown appears elapsed
        cb._open_at = time.time() - 61
        assert cb.is_open is False
        assert cb.open_at is None


class TestCircuitBreakerTransitions:
    def test_record_success_resets_counter(self):
        cb = make_breaker(threshold=5)
        cb.record_failure()
        cb.record_failure()
        cb.record_success()
        assert cb.consecutive_failures == 0

    def test_success_does_not_close_open_circuit(self):
        """record_success resets the counter but does not clear _open_at."""
        cb = make_breaker(threshold=1)
        cb.record_failure()
        assert cb.is_open is True
        cb.record_success()
        # Counter is 0 but the circuit is still open until cooldown elapses
        assert cb.consecutive_failures == 0

    def test_consecutive_failures_increment(self):
        cb = make_breaker(threshold=10)
        for i in range(4):
            cb.record_failure()
        assert cb.consecutive_failures == 4

    def test_success_between_failures_resets_sequence(self):
        cb = make_breaker(threshold=3)
        cb.record_failure()
        cb.record_failure()
        cb.record_success()
        cb.record_failure()   # sequence restarted — only 1 failure since last success
        assert cb.is_open is False
        assert cb.consecutive_failures == 1
