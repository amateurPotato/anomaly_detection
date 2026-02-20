from __future__ import annotations

import time
from typing import Optional


class CircuitBreaker:
    """
    Tracks consecutive LLM failures and opens the circuit after ``threshold`` failures,
    blocking further LLM calls for ``cooldown_seconds``.

    The breaker resets automatically once the cooldown period has elapsed.
    Designed to be composed into AnomalyTracker — it has no dependencies on other
    project modules so it can be reused or tested in complete isolation.
    """

    def __init__(self, threshold: int, cooldown_seconds: float) -> None:
        self._threshold = threshold
        self._cooldown_seconds = cooldown_seconds
        self._consecutive_failures: int = 0
        self._open_at: Optional[float] = None

    # ------------------------------------------------------------------
    # State inspection
    # ------------------------------------------------------------------

    @property
    def is_open(self) -> bool:
        """
        True when the circuit is open (LLM calls should be skipped).

        If the cooldown has elapsed this call resets the breaker to closed
        and returns False, allowing the next request through.
        """
        if self._open_at is None:
            return False
        if time.time() - self._open_at >= self._cooldown_seconds:
            self._open_at = None
            self._consecutive_failures = 0
            print("[CircuitBreaker] Reset — resuming LLM analysis.")
            return False
        return True

    @property
    def consecutive_failures(self) -> int:
        return self._consecutive_failures

    @property
    def open_at(self) -> Optional[float]:
        return self._open_at

    # ------------------------------------------------------------------
    # State transitions
    # ------------------------------------------------------------------

    def record_failure(self) -> None:
        """Increment the consecutive-failure counter; open the circuit at threshold."""
        self._consecutive_failures += 1
        if self._consecutive_failures >= self._threshold and self._open_at is None:
            self._open_at = time.time()
            print(
                f"[CircuitBreaker] CRITICAL: Opened after {self._consecutive_failures} "
                f"consecutive LLM failures. Suspended for {self._cooldown_seconds:.0f}s."
            )

    def record_success(self) -> None:
        """Reset the consecutive-failure counter after a successful LLM call."""
        self._consecutive_failures = 0
