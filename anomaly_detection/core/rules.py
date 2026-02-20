from __future__ import annotations

from collections import deque
from typing import Deque, List, Optional, Tuple

from .models import IPContext


class RuleEngine:
    """
    Symbolic layer: applies deterministic threshold rules to a per-IP window snapshot.

    Intentionally stateless — all inputs come from the caller. Adding a new rule
    means extending ``evaluate`` here without touching AnomalyTracker.
    """

    def __init__(
        self,
        endpoint_threshold: int,
        payload_threshold_bytes: int,
    ) -> None:
        self._endpoint_threshold = endpoint_threshold
        self._payload_threshold = payload_threshold_bytes

    def evaluate(
        self,
        ip: str,
        window: Deque[Tuple[float, str, int]],
    ) -> Optional[IPContext]:
        """
        Apply threshold rules to the current window snapshot.

        Parameters
        ----------
        ip:
            The source IP address being evaluated.
        window:
            Deque of (timestamp, endpoint, payload_size) 3-tuples for this IP.

        Returns
        -------
        IPContext if any rule fires, else None.
        """
        if not window:
            return None

        entries = list(window)
        unique_endpoints = list({ep for _, ep, _ in entries})
        total_payload = sum(ps for _, _, ps in entries)
        triggered_rules: List[str] = []

        if len(unique_endpoints) > self._endpoint_threshold:
            triggered_rules.append("UNIQUE_ENDPOINT_THRESHOLD")

        if total_payload > self._payload_threshold:
            triggered_rules.append("PAYLOAD_THRESHOLD")

        if not triggered_rules:
            return None

        timestamps = [ts for ts, _, _ in entries]
        return IPContext(
            source_ip=ip,
            unique_endpoints=unique_endpoints,
            total_payload_size=total_payload,
            event_count=len(entries),
            window_start=min(timestamps),
            window_end=max(timestamps),
            triggered_rules=triggered_rules,
        )
