# Stream-based Anomaly Detector

A Python security-stream-processor that ingests network logs, applies heuristic rules, and routes
suspicious IP activity to an LLM (local **Ollama** or cloud **Anthropic Claude**) for structured
threat analysis.

---

## How it works

1. Ingests `Event` objects (source IP, endpoint, payload size) in real time.
2. A **rule engine** flags IPs that breach configurable thresholds:
   - More than N unique endpoints in a sliding window, OR
   - Cumulative payload size exceeds a byte threshold.
3. Flagged IPs are batched and sent to an **LLM** for reasoning (exfiltration / recon / false positive).
4. A **circuit breaker** protects the stream if the LLM is unavailable.
5. Results surface via an async `report_callback` as `AnomalyReport` objects.

---

## Prerequisites

| Tool | Version | Required for |
| --- | --- | --- |
| Python | ≥ 3.10 | everything |
| [Ollama](https://ollama.com/download) | any | local LLM mode (default) |
| `ANTHROPIC_API_KEY` env var | — | cloud LLM mode only |

---

## Quick start

### 1 — Clone and set up the environment

```bash
git clone <repo-url>
cd anomaly_detection
make install
```

`make install` creates `.venv/`, installs all runtime and dev dependencies, and installs the package
in editable mode. You only need to run this once (or after adding new dependencies).

### 2 — Pull the local model

```bash
make check-ollama          # verifies Ollama is running and pulls llama3
```

Ollama must be running before this step (`ollama serve` or the desktop app). To use a different
model:

```bash
make check-ollama OLLAMA_MODEL=mistral
```

### 3 — Run the demo

**Local mode (Ollama — default, no API key needed):**

```bash
make demo
```

**Cloud mode (Anthropic Claude):**

```bash
export ANTHROPIC_API_KEY=sk-...
make demo-cloud
```

**Override the Ollama model or URL:**

```bash
make demo OLLAMA_MODEL=mistral
make demo OLLAMA_BASE_URL=http://192.168.1.10:11434
```

---

## Running tests

```bash
make test          # full suite + branch coverage (fails if < 100%)
make test-fast     # full suite, no coverage  (faster feedback)
make test-llm      # only LLM analyser unit tests
make test-tracker  # only tracker integration tests
make test-demo     # only simulator tests
```

All tests are fully offline — LLM calls are mocked, no Ollama or API key needed.

---

## Configuration reference

`TrackerConfig` controls all runtime behaviour. Pass it to `AnomalyTracker`:

| Field | Default | Description |
| --- | --- | --- |
| `window_seconds` | `60` | Sliding window duration per IP |
| `unique_endpoint_threshold` | `10` | Unique endpoints to trigger the rule |
| `payload_threshold_bytes` | `10 MB` | Total payload to trigger the rule |
| `micro_batch_seconds` | `10.0` | How often the LLM batch is flushed |
| `max_queue_size` | `10 000` | Max pending contexts |
| `stale_window_seconds` | `300` | Idle TTL before an IP window is evicted |
| `circuit_breaker_threshold` | `5` | Consecutive LLM failures before opening |
| `circuit_breaker_cooldown_seconds` | `60.0` | Seconds the circuit stays open |
| `use_cloud_llm` | `False` | `False` = local Ollama, `True` = Anthropic Claude |
| `ollama_model` | `"llama3"` | Local model name |
| `ollama_base_url` | `"http://localhost:11434"` | Ollama server URL |

---

## Usage in code

### Local Ollama (default)

```python
import asyncio
from anomaly_detection import AnomalyTracker, Event, TrackerConfig

config = TrackerConfig(unique_endpoint_threshold=10, micro_batch_seconds=10.0)
# use_cloud_llm=False is the default — no API key needed
tracker = AnomalyTracker(config=config)

async def on_report(report):
    print(report.context.source_ip, report.analysis.threat_score)

tracker = AnomalyTracker(config=config, report_callback=on_report)
await tracker.start()
await tracker.ingest_event(Event(source_ip="1.2.3.4", endpoint="/api/data", payload_size=500))
await tracker.stop()
```

### Cloud (Anthropic Claude)

```python
import anthropic
from anomaly_detection import AnomalyTracker, TrackerConfig

config = TrackerConfig(use_cloud_llm=True)
client = anthropic.AsyncAnthropic(api_key="sk-...")
tracker = AnomalyTracker(config=config, anthropic_client=client)
```

### Switching between backends at runtime

```python
config = TrackerConfig(
    use_cloud_llm=True,          # flip to False for local
    ollama_model="mistral",      # model used when use_cloud_llm=False
    ollama_base_url="http://localhost:11434",
)
```

---

## Package layout

```text
anomaly_detection/
├── core/
│   ├── models.py        # Event, IPContext, LLMAnalysis, AnomalyReport, TrackerConfig
│   └── rules.py         # RuleEngine (endpoint + payload thresholds)
├── engine/
│   ├── tracker.py       # AnomalyTracker — main orchestrator
│   └── circuit_breaker.py
├── llm/
│   └── analyser.py      # LLMAnalyser (Claude) + LocalLLMAnalyser (Ollama)
├── demo/
│   └── simulator.py     # End-to-end demo entry point
└── tests/
    ├── conftest.py       # Shared fixtures + mock helpers
    ├── core/
    ├── engine/
    ├── llm/
    └── demo/
```

---

## Environment variables

| Variable | Default | Purpose |
| --- | --- | --- |
| `USE_CLOUD_LLM` | `false` | Set to `true` to use Anthropic Claude in the demo |
| `ANTHROPIC_API_KEY` | — | Required when `USE_CLOUD_LLM=true` |
| `OLLAMA_MODEL` | `llama3` | Local model name (demo only) |
| `OLLAMA_BASE_URL` | `http://localhost:11434` | Ollama server URL (demo only) |
