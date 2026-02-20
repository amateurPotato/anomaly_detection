from __future__ import annotations

import asyncio
import time
import uuid
from collections import defaultdict, deque
from typing import Awaitable, Callable, Deque, Dict, List, Optional, Tuple

import anthropic

from ..core.models import AnomalyReport, Event, IPContext, TrackerConfig
from ..core.rules import RuleEngine
from ..llm import LLMAnalyser, LocalLLMAnalyser
from .circuit_breaker import CircuitBreaker


class AnomalyTracker:
    """
    Orchestrator: wires RuleEngine, CircuitBreaker, and LLMAnalyser together
    behind a simple async event-ingestion interface.

    Responsibilities
    ----------------
    1. Maintain per-IP sliding windows (deque of (timestamp, endpoint, payload_size) 3-tuples).
    2. Delegate rule evaluation to RuleEngine after every event.
    3. Accumulate flagged IPContext objects in a micro-batch buffer.
    4. Every ``config.micro_batch_seconds``, flush the buffer via LLMAnalyser (guarded by
       CircuitBreaker) and evict stale windows.
    5. Emit AnomalyReport objects via an optional async callback.

    Hybrid LLM
    ----------
    When ``config.use_cloud_llm=False`` (default) the local Ollama model is used.
    Set ``config.use_cloud_llm=True`` and pass an ``anthropic_client`` to use Claude.
    """

    def __init__(
        self,
        config: TrackerConfig = TrackerConfig(),
        report_callback: Optional[Callable[[AnomalyReport], Awaitable[None]]] = None,
        anthropic_client: Optional[anthropic.AsyncAnthropic] = None,
    ) -> None:
        self._config = config
        self._report_callback = report_callback

        # Per-IP sliding windows: ip -> deque of (timestamp, endpoint, payload_size)
        self._windows: Dict[str, Deque[Tuple[float, str, int]]] = defaultdict(deque)

        self._pending_contexts: List[IPContext] = []
        self._batch_lock = asyncio.Lock()

        self._flush_task: Optional[asyncio.Task] = None
        self._running = False
        self._active_llm_tasks: set[asyncio.Task] = set()

        # Composed components — each independently testable
        self._rules = RuleEngine(
            endpoint_threshold=config.unique_endpoint_threshold,
            payload_threshold_bytes=config.payload_threshold_bytes,
        )
        self._circuit_breaker = CircuitBreaker(
            threshold=config.circuit_breaker_threshold,
            cooldown_seconds=config.circuit_breaker_cooldown_seconds,
        )

        # Select LLM backend based on config flag
        if config.use_cloud_llm:
            if anthropic_client is None:
                raise ValueError(
                    "anthropic_client is required when use_cloud_llm=True"
                )
            self._llm: LLMAnalyser | LocalLLMAnalyser = LLMAnalyser(client=anthropic_client)
        else:
            self._llm = LocalLLMAnalyser(
                base_url=config.ollama_base_url,
                model=config.ollama_model,
            )

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def start(self) -> None:
        """Spawn the background micro-batch flush loop."""
        self._running = True
        self._flush_task = asyncio.create_task(self._flush_loop())

    async def stop(self) -> None:
        """Cancel the flush loop, wait for any in-progress LLM tasks, then drain remaining."""
        self._running = False
        if self._flush_task:
            self._flush_task.cancel()
            try:
                await self._flush_task
            except asyncio.CancelledError:
                pass
        # LLM tasks are shielded from flush-loop cancellation — wait for them here.
        if self._active_llm_tasks:
            await asyncio.gather(*list(self._active_llm_tasks), return_exceptions=True)
        await self._flush_pending()

    # ------------------------------------------------------------------
    # Event ingestion
    # ------------------------------------------------------------------

    async def ingest_event(self, event: Event) -> None:
        """
        Process one Event:
        1. Evict expired entries from this IP's sliding window.
        2. Append the new entry.
        3. Evaluate rules via RuleEngine.
        4. If rules fire, add (or replace) an IPContext in the micro-batch buffer.
        """
        ip = event.source_ip
        window = self._windows[ip]

        cutoff = event.timestamp - self._config.window_seconds
        while window and window[0][0] < cutoff:
            window.popleft()

        window.append((event.timestamp, event.endpoint, event.payload_size))

        context = self._rules.evaluate(ip, window)
        if context is None:
            return

        async with self._batch_lock:
            self._pending_contexts = [
                c for c in self._pending_contexts if c.source_ip != ip
            ]
            self._pending_contexts.append(context)

    # ------------------------------------------------------------------
    # Micro-batch flush loop
    # ------------------------------------------------------------------

    async def _flush_loop(self) -> None:
        """Background task: flush pending contexts and evict stale windows every micro_batch_seconds."""
        while self._running:
            await asyncio.sleep(self._config.micro_batch_seconds)
            await self._flush_pending()
            self._cleanup_stale_windows()

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
        for task in tasks:
            self._active_llm_tasks.add(task)
            task.add_done_callback(self._active_llm_tasks.discard)
        try:
            # Shield protects tasks from cancellation when the flush loop is cancelled.
            # stop() then waits for any surviving tasks via _active_llm_tasks.
            await asyncio.shield(asyncio.gather(*tasks, return_exceptions=True))
        except asyncio.CancelledError:
            pass  # tasks continue; stop() will await them

    def _cleanup_stale_windows(self) -> None:
        """
        Remove per-IP windows idle for longer than stale_window_seconds.

        An IP is stale when its most recent event (window[-1][0]) is older than
        ``now - stale_window_seconds``. Prevents unbounded memory growth.
        """
        cutoff = time.time() - self._config.stale_window_seconds
        stale = [
            ip for ip, window in self._windows.items()
            if not window or window[-1][0] < cutoff
        ]
        for ip in stale:
            del self._windows[ip]

    async def _analyze_and_emit(self, context: IPContext, batch_id: str) -> None:
        """
        Delegate to LLMAnalyser (guarded by CircuitBreaker), build an AnomalyReport,
        and emit via callback. Exceptions are always caught to protect the event stream.
        """
        if self._circuit_breaker.is_open:
            return

        try:
            analysis = await self._llm.analyse(context)
            self._circuit_breaker.record_success()
            report = AnomalyReport(
                context=context,
                analysis=analysis,
                batch_id=batch_id,
            )
            if self._report_callback:
                await self._report_callback(report)
        except Exception as exc:
            self._circuit_breaker.record_failure()
            print(f"[AnomalyTracker] LLM analysis failed for {context.source_ip}: {exc}")
