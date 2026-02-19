# Project Overview: Security Anomaly Engine

- Goals: Realtime telemetry analysis
- Strategy: Hybrid (Rules + LLM analysis)
- Quality: Strict Pydantic, and 100% test coverage
- Batching: Use 10-second micro-batches for LLM context to optimize token usage.
- Concurrency: Use Python `asyncio` to prevent blocking the stream during LLM inference.
