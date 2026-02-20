# Project Overview: Security Anomaly Engine

- Goals: Realtime telemetry analysis
- Strategy: Hybrid (Rules + LLM analysis)
- Quality: Strict Pydantic, and 100% test coverage
- Batching: Use 10-second micro-batches for LLM context to optimize token usage.
- Concurrency: Use Python `asyncio` to prevent blocking the stream during LLM inference.

## Layered package layout

The project uses a layered package structure under `anomaly_detection/`:

| Layer   | Package               | Contents |
|---------|------------------------|----------|
| Core    | `anomaly_detection.core` | `models.py` (Event, IPContext, TrackerConfig, etc.), `rules.py` (RuleEngine) |
| Engine  | `anomaly_detection.engine` | `circuit_breaker.py`, `tracker.py` (AnomalyTracker) |
| LLM     | `anomaly_detection.llm` | `analyser.py` (LLMAnalyser, ANALYSIS_TOOL_SCHEMA) |
| Demo    | `anomaly_detection.demo` | `simulator.py` (run_simulation, main, run_main) |

**Canonical imports:** Prefer importing from the top-level package or the specific subpackage:

- `from anomaly_detection import AnomalyTracker, Event, run_simulation`
- `from anomaly_detection.core.models import Event, TrackerConfig`
- `from anomaly_detection.engine import AnomalyTracker, CircuitBreaker`
- `from anomaly_detection.llm import LLMAnalyser, ANALYSIS_TOOL_SCHEMA`
- `from anomaly_detection.demo import main, run_simulation`

Tests mirror this layout under `tests/core/`, `tests/engine/`, `tests/llm/`, `tests/demo/`.
