from __future__ import annotations

import asyncio
import time
import uuid
from collections import defaultdict, deque
from typing import Callable, Awaitable, Deque, Dict, List, Optional, Tuple

import anthropic

from .models import AnomalyReport, Event, IPContext, LLMAnalysis, TrackerConfig

# ---------------------------------------------------------------------------
# Tool schema registered with Claude to force structured JSON output.
# The schema mirrors LLMAnalysis exactly so model_validate() acts as the
# final validation gate after the API call.
# ---------------------------------------------------------------------------
ANALYSIS_TOOL_SCHEMA = {
    "name": "report_anomaly_analysis",
    "description": (
        "Report the structured security analysis of suspicious IP activity. "
        "You MUST call this tool with your analysis. Do not add free-form text."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "threat_score": {
                "type": "number",
                "minimum": 0.0,
                "maximum": 1.0,
                "description": "Probability of malicious activity (0.0=benign, 1.0=confirmed threat).",
            },
            "observations": {
                "type": "array",
                "items": {"type": "string"},
                "minItems": 1,
                "description": "Specific observations about the activity.",
            },
            "suggested_mitigation": {
                "type": "string",
                "description": "Concrete recommended action.",
            },
        },
        "required": ["threat_score", "observations", "suggested_mitigation"],
    },
}


class AnomalyTracker:
    """
    Stateful, async-safe anomaly detection engine.

    Responsibilities
    ----------------
    1. Maintain per-IP sliding windows (deque of (timestamp, endpoint, payload_size) 3-tuples).
    2. Apply deterministic threshold rules after every event ingestion (symbolic layer).
    3. Accumulate flagged IPContext objects in a micro-batch buffer.
    4. Every ``config.micro_batch_seconds``, flush the buffer to ``analyze_with_llm`` (neural layer).
    5. Emit AnomalyReport objects via an optional async callback.
    """

    def __init__(
        self,
        anthropic_client: anthropic.AsyncAnthropic,
        config: TrackerConfig = TrackerConfig(),
        report_callback: Optional[Callable[[AnomalyReport], Awaitable[None]]] = None,
    ) -> None:
        self._client = anthropic_client
        self._config = config
        self._report_callback = report_callback

        # ip -> deque of (timestamp, endpoint, payload_size)
        self._windows: Dict[str, Deque[Tuple[float, str, int]]] = defaultdict(deque)

        self._pending_contexts: List[IPContext] = []
        self._batch_lock = asyncio.Lock()

        self._flush_task: Optional[asyncio.Task] = None
        self._running = False

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def start(self) -> None:
        """Spawn the background micro-batch flush loop."""
        self._running = True
        self._flush_task = asyncio.create_task(self._flush_loop())

    async def stop(self) -> None:
        """Cancel the flush loop and drain any remaining pending contexts."""
        self._running = False
        if self._flush_task:
            self._flush_task.cancel()
            try:
                await self._flush_task
            except asyncio.CancelledError:
                pass
        await self._flush_pending()

    # ------------------------------------------------------------------
    # Event ingestion
    # ------------------------------------------------------------------

    async def ingest_event(self, event: Event) -> None:
        """
        Process one Event:
        1. Evict expired entries from this IP's sliding window.
        2. Append the new entry.
        3. Evaluate deterministic rules.
        4. If rules fire, add (or replace) an IPContext in the micro-batch buffer.
        """
        ip = event.source_ip
        window = self._windows[ip]

        # Step 1 — evict entries outside the 60-second window
        cutoff = event.timestamp - self._config.window_seconds
        while window and window[0][0] < cutoff:
            window.popleft()

        # Step 2 — append
        window.append((event.timestamp, event.endpoint, event.payload_size))

        # Step 3 — rule evaluation
        context = self._evaluate_rules(ip, window)
        if context is None:
            return

        # Step 4 — add to micro-batch buffer (dedup: keep latest context per IP)
        async with self._batch_lock:
            self._pending_contexts = [
                c for c in self._pending_contexts if c.source_ip != ip
            ]
            self._pending_contexts.append(context)

    # ------------------------------------------------------------------
    # Rule engine (symbolic layer)
    # ------------------------------------------------------------------

    def _evaluate_rules(
        self,
        ip: str,
        window: Deque[Tuple[float, str, int]],
    ) -> Optional[IPContext]:
        """
        Apply threshold rules to the current window snapshot.
        Returns an IPContext if any rule fires, else None.
        """
        if not window:
            return None

        entries = list(window)
        unique_endpoints = list({ep for _, ep, _ in entries})
        total_payload = sum(ps for _, _, ps in entries)
        triggered_rules: List[str] = []

        if len(unique_endpoints) > self._config.unique_endpoint_threshold:
            triggered_rules.append("UNIQUE_ENDPOINT_THRESHOLD")

        if total_payload > self._config.payload_threshold_bytes:
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

    # ------------------------------------------------------------------
    # Micro-batch flush loop
    # ------------------------------------------------------------------

    async def _flush_loop(self) -> None:
        """Background task: flush pending contexts every micro_batch_seconds."""
        while self._running:
            await asyncio.sleep(self._config.micro_batch_seconds)
            await self._flush_pending()

    async def _flush_pending(self) -> None:
        """
        Atomically drain _pending_contexts and dispatch each to the LLM concurrently.
        Uses return_exceptions=True so one failure doesn't cancel the rest of the batch.
        """
        async with self._batch_lock:
            batch = self._pending_contexts[:]
            self._pending_contexts.clear()

        if not batch:
            return

        batch_id = str(uuid.uuid4())
        tasks = [
            asyncio.create_task(self._analyze_and_emit(ctx, batch_id))
            for ctx in batch
        ]
        await asyncio.gather(*tasks, return_exceptions=True)

    async def _analyze_and_emit(self, context: IPContext, batch_id: str) -> None:
        """
        Call analyze_with_llm, build an AnomalyReport, and emit via callback.
        Exceptions are caught here so a single LLM failure cannot crash the engine.
        """
        try:
            analysis = await self.analyze_with_llm(context)
            report = AnomalyReport(
                context=context,
                analysis=analysis,
                batch_id=batch_id,
            )
            if self._report_callback:
                await self._report_callback(report)
        except Exception as exc:
            print(f"[AnomalyTracker] LLM analysis failed for {context.source_ip}: {exc}")

    # ------------------------------------------------------------------
    # LLM analysis (neural layer)
    # ------------------------------------------------------------------

    async def analyze_with_llm(self, context: IPContext) -> LLMAnalysis:
        """
        Send IPContext to Claude via the async Anthropic client.

        Forces structured output via tool_choice so the response is guaranteed
        to be a JSON object that maps 1-to-1 onto LLMAnalysis.

        Raises
        ------
        ValueError
            If Claude returns no tool_use block (defensive guard against SDK changes).
        pydantic.ValidationError
            If Claude's JSON violates the LLMAnalysis schema (e.g. threat_score > 1.0).
        """
        response = await self._client.messages.create(
            model="claude-opus-4-6",
            max_tokens=1024,
            tools=[ANALYSIS_TOOL_SCHEMA],
            tool_choice={"type": "tool", "name": "report_anomaly_analysis"},
            messages=[{"role": "user", "content": self._build_prompt(context)}],
        )

        tool_use_block = next(
            (block for block in response.content if block.type == "tool_use"),
            None,
        )
        if tool_use_block is None:
            raise ValueError(
                f"Claude did not return a tool_use block for IP {context.source_ip}. "
                f"stop_reason={response.stop_reason}"
            )

        return LLMAnalysis.model_validate(tool_use_block.input)

    def _build_prompt(self, context: IPContext) -> str:
        """Token-efficient prompt constructed from IPContext."""
        endpoint_list = context.unique_endpoints[:20]
        truncation_note = (
            "...(truncated)" if len(context.unique_endpoints) > 20 else ""
        )
        return (
            f"Analyze this suspicious network activity:\n\n"
            f"Source IP: {context.source_ip}\n"
            f"Triggered rules: {', '.join(context.triggered_rules)}\n"
            f"Unique endpoints accessed: {len(context.unique_endpoints)}\n"
            f"Endpoints: {', '.join(endpoint_list)}{truncation_note}\n"
            f"Total payload transferred: {context.total_payload_size:,} bytes\n"
            f"Events in window: {context.event_count}\n"
            f"Window duration: {context.window_end - context.window_start:.1f}s\n\n"
            f"Determine if this is data exfiltration, reconnaissance, or a false positive. "
            f"Call the report_anomaly_analysis tool with your structured assessment.\n\n"
            f"Reasoning tip: Prioritize identifying Lateral Movement patterns "
            f"(e.g. systematic scanning of internal endpoints, credential-access staging, "
            f"east-west traversal). These are high-priority threats for this architecture."
        )


# ---------------------------------------------------------------------------
# Event stream simulator
# ---------------------------------------------------------------------------

async def run_simulation(
    tracker: AnomalyTracker,
    events: List[Event],
    inter_event_delay: float = 0.01,
) -> None:
    """
    Simulate a continuous event stream by pushing events into the tracker.
    In production this would be replaced by a Kafka/Kinesis consumer.
    """
    for event in events:
        await tracker.ingest_event(event)
        await asyncio.sleep(inter_event_delay)


async def main() -> None:
    """End-to-end demo. Requires ANTHROPIC_API_KEY in the environment."""
    import os

    config = TrackerConfig(
        window_seconds=60,
        unique_endpoint_threshold=10,
        payload_threshold_bytes=10 * 1024 * 1024,
        micro_batch_seconds=10.0,
    )

    client = anthropic.AsyncAnthropic(api_key=os.environ["ANTHROPIC_API_KEY"])
    reports: List[AnomalyReport] = []

    async def on_report(report: AnomalyReport) -> None:
        reports.append(report)
        print(
            f"[ALERT] {report.context.source_ip} | "
            f"score={report.analysis.threat_score:.2f} | "
            f"rules={report.context.triggered_rules}"
        )
        print(f"  Mitigation: {report.analysis.suggested_mitigation}")
        for obs in report.analysis.observations:
            print(f"  - {obs}")

    tracker = AnomalyTracker(
        anthropic_client=client,
        config=config,
        report_callback=on_report,
    )

    now = time.time()
    events: List[Event] = []

    # Suspicious IP: hits 15 unique endpoints (threshold=10 → triggers)
    for i in range(15):
        events.append(
            Event(
                source_ip="192.168.1.100",
                endpoint=f"/api/resource/{i}",
                payload_size=500_000,
                timestamp=now + i * 2,
            )
        )

    # Benign IP: only hits 3 unique endpoints
    for i in range(5):
        events.append(
            Event(
                source_ip="10.0.0.50",
                endpoint="/api/health",
                payload_size=1_024,
                timestamp=now + i * 3,
            )
        )

    await tracker.start()
    try:
        await run_simulation(tracker, events, inter_event_delay=0.1)
        await asyncio.sleep(config.micro_batch_seconds + 1)
    finally:
        await tracker.stop()

    print(f"\nTotal anomaly reports generated: {len(reports)}")


if __name__ == "__main__":
    asyncio.run(main())
