# Stream-based Anomaly Detector

This project is a security-stream-processor.

## Problem Statement

We have firehose of network logs (JSON). We need a service that:

1. Ingests these logs.
2. Uses an LLM/Heuristic hybrid to flag 'suspicious' activity.
3. Maintains a stateful 'threat score' for different IP addresses.
4. Ensures the logic is explainable.

### Technical hurdle

This is a Python service that processes a stream of 'Event' objects. An Event has a source_ip, endpoint, and payload_size. If an IP hits more than 10 unique endpoints in 1 minute, OR if its cumulative payload_size exceeds a threshold, we need to send that context to an LLM to 'reason' if this is data exfiltration or a false positive.

## Installation

From the project root:

```bash
pip install -e .
```

For development (tests, coverage):

```bash
pip install -e ".[dev]"
```

## Running the demo

Set your API key and run the end-to-end demo:

```bash
export ANTHROPIC_API_KEY=your_key
anomaly-demo
```

Or via Python:

```bash
python -m anomaly_detection.demo.simulator
```

## Running tests

From the project root:

```bash
pytest
```

With coverage:

```bash
pytest --cov=anomaly_detection --cov-report=term-missing
```

## Package layout

The code is organized in a layered package:

- **anomaly_detection.core** — Domain models (`Event`, `IPContext`, `TrackerConfig`, etc.) and the rule engine.
- **anomaly_detection.engine** — Circuit breaker and `AnomalyTracker` (orchestrator).
- **anomaly_detection.llm** — LLM analyser (Claude integration).
- **anomaly_detection.demo** — Simulator and `main` entry point.

## Usage

```python
from anomaly_detection import AnomalyTracker, Event, TrackerConfig, run_simulation

config = TrackerConfig(unique_endpoint_threshold=10, micro_batch_seconds=10.0)
tracker = AnomalyTracker(anthropic_client=client, config=config)

await tracker.start()
# Ingest events (e.g. from Kafka/Kinesis) via tracker.ingest_event(event)
await tracker.stop()
```
