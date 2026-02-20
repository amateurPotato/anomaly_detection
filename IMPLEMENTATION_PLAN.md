# Implementation Plan: Security Anomaly Engine

## 1. Overview

A hybrid symbolic-neural engine for real-time network-log anomaly detection. It ingests a
continuous stream of JSON network events, applies deterministic threshold rules to maintain
per-IP sliding windows, and escalates suspicious activity to Claude (LLM) for contextual
threat assessment. Results are emitted as fully-typed `AnomalyReport` objects via an async
callback, enabling downstream consumers (alerting, SIEM, dashboards) to act without coupling
to the engine internals.

---

## 2. Architecture

```
Event Stream (simulated asyncio loop)
        |
        v
   AnomalyTracker.ingest_event()
        |
        v
   Sliding Window  <-- deque per IP, 60-second TTL
   Rule Engine     <-- unique_endpoints > 10  OR  payload > 10 MB
        |
        |-- no breach: discard
        |
        v
   Micro-batch Buffer  <-- asyncio.Lock, dedup by IP
        |
        | (every 10 seconds)
        v
   analyze_with_llm()  <-- Claude Opus 4.6, forced tool_use
        |
        v
   LLMAnalysis (Pydantic-validated)
        |
        v
   AnomalyReport  -->  report_callback
```

- Raw Data (Event): Individual log entries enter through ingest_event.
- Symbolic Reasoning (_evaluate_rules): This is the first gate. It uses hard-coded thresholds (unique endpoints, payload size). If no rules fire, the process stops here.
- Structured Representation (IPContext): If a rule fires, the raw window of data is distilled into a structured object containing only the relevant metadata.
- Neural Network (analyze_with_llm): The structured context is sent to Claude. The LLM performs the high-level reasoning (detecting "Lateral Movement" or "Exfiltration").
- Final Output (AnomalyReport): The final output is produced, combining the symbolic triggers with the neural threat score and mitigation steps.
  
---

## 3. Key Design Decisions

| Decision | Rationale |
| --- | --- |
| `deque` for sliding window | O(1) amortised eviction from the left; 3-tuples keep memory lean |
| Micro-batching (10 s) | Amortises LLM latency; matches CLAUDE.md batching requirement |
| Forced `tool_use` | Guarantees structured JSON from Claude; Pydantic is the final guard |
| Dedup in batch buffer | Same IP triggering twice before flush → only latest context sent to LLM |
| `return_exceptions=True` in gather | One LLM failure cannot cancel concurrent IP analyses |
| `TrackerConfig` as Pydantic model | Thresholds injected at construction; tests override freely |

---

## 4. Pydantic Models (`src/models.py`)

| Model | Purpose |
| --- | --- |
| `Event` | Raw telemetry: `source_ip`, `endpoint`, `payload_size`, `timestamp` |
| `IPContext` | Window snapshot passed to LLM when rules fire |
| `LLMAnalysis` | Claude output: `threat_score`, `observations`, `suggested_mitigation` |
| `AnomalyReport` | Final record: `IPContext` + `LLMAnalysis` + `batch_id` |
| `TrackerConfig` | Injected config with production defaults |

All models use strict Pydantic v2 field validators. `LLMAnalysis.threat_score` is bounded
`ge=0.0, le=1.0` so a hallucinated value is rejected before it can propagate downstream.

---

## 5. Hybrid Logic Detail

### Symbolic layer — `_evaluate_rules()` (`src/anomaly_tracker.py`)

- Unique endpoint count is derived with a set comprehension
  (`{ep for _, ep, _ in entries}`), so repeated visits to the same endpoint never
  inflate the counter.
- Both rules can fire simultaneously; `triggered_rules` is a `List[str]`, not an enum,
  keeping the schema open for future rules without breaking changes.
- Returns `None` when no rule fires — no allocation, no lock contention.

### Neural layer — `analyze_with_llm()` (`src/anomaly_tracker.py`)

- `tool_choice={"type": "tool", "name": "report_anomaly_analysis"}` forces Claude to
  call the registered tool rather than return free text, making structured output
  reliable rather than prompt-dependent.
- `LLMAnalysis.model_validate(block.input)` is the final validation gate.
- Every prompt ends with a **Reasoning Tip**:

  > _"Prioritize identifying Lateral Movement patterns (e.g. systematic scanning of
  > internal endpoints, credential-access staging, east-west traversal). These are
  > high-priority threats for this architecture."_

---

## 6. Concurrency Model

```
Main coroutine:   ingest_event() --> _evaluate_rules() --> _pending_contexts (locked)
Background task:  _flush_loop()  --> _flush_pending()  --> asyncio.gather(per-IP LLM calls)
```

`asyncio.Lock` (`_batch_lock`) serialises all reads and writes to `_pending_contexts`.
The flush loop and the ingestion path never block each other beyond the lock acquisition.
LLM calls for multiple IPs in the same batch run concurrently via `asyncio.gather`.

`stop()` cancels the background task and then calls `_flush_pending()` directly, ensuring
no events are silently dropped on graceful shutdown.

---

## 7. Testing Strategy (`tests/test_anomaly_tracker.py`)

- **No real API calls** — `AsyncMock` replaces `anthropic.AsyncAnthropic` entirely.
- `TrackerConfig` with small thresholds (`unique_endpoint_threshold=3`,
  `payload_threshold_bytes=1000`, `micro_batch_seconds=0.1`) makes async integration
  tests complete in under a second.
- Coverage target: **100% branch coverage** (`fail_under = 100` in `pyproject.toml`).

| Test class | What it covers |
| --- | --- |
| `TestEventModel` | All `Event` validators: IP format, empty endpoint, negative payload |
| `TestLLMAnalysis` | `threat_score` out-of-range (hi/lo), empty observations, empty mitigation |
| `TestTrackerConfig` | Defaults, overrides |
| `TestEvaluateRules` | Both rules; each rule alone; below thresholds; empty window; dedup |
| `TestSlidingWindowEviction` | Eviction at boundary; retention within window; new IP |
| `TestMicroBatchDeduplication` | Same IP replaced before flush |
| `TestAnalyzeWithLLM` | Valid response; correct API params; missing tool_use block; bad schema |
| `TestBuildPrompt` | IP/rules present; truncation at 20 endpoints; Lateral Movement tip |
| `TestLifecycle` | start/stop; callback on alert; benign no-alert; LLM error resilience; final flush |
| `TestRunSimulation` | All events ingested; empty list no-op |

---

## 8. File Reference

```
anomaly_detection/
├── src/
│   ├── models.py            # All Pydantic models
│   └── anomaly_tracker.py   # AnomalyTracker class + ANALYSIS_TOOL_SCHEMA + simulator
├── tests/
│   └── test_anomaly_tracker.py  # 100% coverage suite (AsyncMock, pytest-asyncio)
├── requirements.txt         # anthropic, pydantic, pytest, pytest-asyncio, pytest-cov
├── pyproject.toml           # asyncio_mode=auto, branch coverage, fail_under=100
└── CLAUDE.md                # Project constraints (batching, concurrency, quality)
```

---

## 9. Running the Project

```bash
# Install dependencies (use the project venv if present)
pip install -r requirements.txt

# Run tests with branch coverage report
pytest tests/ --cov=src --cov-report=term-missing

# Live demo — fires real Claude API calls
ANTHROPIC_API_KEY=<your-key> python -m src.anomaly_tracker
```
