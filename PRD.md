# Product Requirements Document
## Security Anomaly Engine — Stream-based Anomaly Detector

**Version:** 1.0
**Date:** 2026-02-19
**Status:** Active Development

---

## 1. Problem Statement

Security operations teams are drowning in network telemetry. A firehose of JSON network logs
arrives continuously, and the signal-to-noise ratio is too low for purely rule-based systems
to handle reliably. Simple threshold alerts produce too many false positives; pure ML models
lack explainability; and human analysts cannot review every event in real time.

**The gap:** There is no lightweight, explainable, real-time service that combines fast
deterministic rules with LLM reasoning to flag only the events worth investigating — and
explain *why*.

---

## 2. Goals

| # | Goal |
| --- | --- |
| G1 | Detect suspicious IP behaviour (reconnaissance, lateral movement, data exfiltration) in real time |
| G2 | Maintain a stateful, per-IP threat score that updates as new events arrive |
| G3 | Produce fully explainable verdicts — every alert includes observations and a mitigation action |
| G4 | Keep false-positive rates low by gating LLM calls behind deterministic rules |
| G5 | Minimise LLM token costs via micro-batching |

---

## 3. Non-Goals

- This service does **not** block traffic in real time (it is advisory only).
- This service does **not** replace a SIEM — it feeds one.
- This service does **not** persist state across restarts (in-memory only, v1).
- This service does **not** handle authentication or authorisation of event producers.

---

## 4. Users

| Persona | Need |
| --- | --- |
| **SOC Analyst** | Receive ranked, explainable alerts with suggested mitigations; stop reviewing raw logs |
| **Security Engineer** | Tune thresholds and rules without redeploying; integrate with existing SIEM |
| **Platform Engineer** | Embed the engine in a larger pipeline (Kafka, Kinesis, etc.) via the callback interface |

---

## 5. Event Schema

Each network log event contains:

| Field | Type | Description |
| --- | --- | --- |
| `source_ip` | `str` | IPv4 or IPv6 address of the originating host |
| `endpoint` | `str` | URI path accessed (e.g. `/api/users/export`) |
| `payload_size` | `int` | Request/response payload in bytes (non-negative) |
| `timestamp` | `float` | Unix epoch (defaults to ingestion time if omitted) |

---

## 6. Detection Rules (Symbolic Layer)

Rules are evaluated after every event. Multiple rules can fire simultaneously.

| Rule ID | Condition | Signal |
| --- | --- | --- |
| `UNIQUE_ENDPOINT_THRESHOLD` | IP hits > 10 unique endpoints within 60 seconds | Reconnaissance / scanning |
| `PAYLOAD_THRESHOLD` | Cumulative payload from an IP exceeds 10 MB within 60 seconds | Data exfiltration |

Both thresholds are configurable at startup via `TrackerConfig`.

---

## 7. LLM Reasoning (Neural Layer)

When any rule fires, the engine batches the triggering IP context and sends it to Claude
(claude-opus-4-6) every 10 seconds. Claude is asked to return a structured verdict via
forced tool-use — not free text — to guarantee machine-parseable output.

### Required LLM output fields

| Field | Type | Constraint | Description |
| --- | --- | --- | --- |
| `threat_score` | `float` | 0.0 – 1.0 | Probability the activity is malicious |
| `observations` | `List[str]` | ≥ 1 item | Specific reasoning behind the score |
| `suggested_mitigation` | `str` | non-empty | Concrete recommended action |

### Reasoning priority

The LLM prompt instructs Claude to prioritise **Lateral Movement** patterns:

- Systematic scanning of internal endpoints
- Credential-access staging
- East-west (intra-network) traversal

---

## 8. Functional Requirements

| ID | Requirement |
| --- | --- |
| FR-1 | The engine MUST process events asynchronously without blocking the ingestion loop |
| FR-2 | The engine MUST maintain a 60-second sliding window per `source_ip` using `collections.deque` |
| FR-3 | The engine MUST evict window entries in real time as they age out |
| FR-4 | The engine MUST de-duplicate pending LLM context: if the same IP triggers rules twice before a batch flush, only the latest context is sent |
| FR-5 | The engine MUST batch pending contexts and flush them to the LLM every 10 seconds |
| FR-6 | The engine MUST validate all LLM output against the `LLMAnalysis` Pydantic schema; invalid output MUST raise an error, not silently pass |
| FR-7 | The engine MUST continue processing new events if a single LLM call fails |
| FR-8 | Calling `stop()` MUST flush any remaining pending contexts before shutdown |
| FR-9 | All data models MUST use strict Pydantic v2 validation |
| FR-10 | The `report_callback` interface MUST be async to avoid blocking the engine |

---

## 9. Non-Functional Requirements

| ID | Requirement |
| --- | --- |
| NFR-1 | **Test coverage:** 100% branch coverage enforced in CI |
| NFR-2 | **Explainability:** Every `AnomalyReport` MUST include `observations` and `suggested_mitigation` |
| NFR-3 | **Token efficiency:** LLM prompts MUST cap endpoint lists at 20 items and use terse formatting |
| NFR-4 | **Resilience:** A network timeout or malformed LLM response MUST NOT crash the engine |
| NFR-5 | **Configurability:** All thresholds (window, endpoint count, payload, batch interval) MUST be overridable without code changes |

---

## 10. Out-of-Scope (Future Iterations)

- Persistent storage of `AnomalyReport` records (database / object store)
- REST or gRPC API for external event producers
- Adaptive threshold learning from historical data
- Multi-model LLM routing (fall back to a cheaper model for low-confidence verdicts)
- Rate limiting per source IP at the ingestion layer
- Horizontal scaling / stateful stream processing (Apache Flink, Kafka Streams)

---

## 11. Success Metrics

| Metric | Target |
| --- | --- |
| False-positive rate | < 5% of generated alerts are confirmed benign by analysts |
| Alert latency | Alert emitted within 20 seconds of the threshold-breaching event |
| LLM call cost | < 1 API call per 10-second window per unique flagged IP |
| Test coverage | 100% branch coverage on every merge |
| Engine uptime | LLM failures do not cause ingestion downtime |

---

## 12. Dependencies

| Dependency | Version | Purpose |
| --- | --- | --- |
| `anthropic` | ≥ 0.26.0 | Async Claude API client with tool-use support |
| `pydantic` | ≥ 2.7.0 | Strict data validation for all models |
| `pytest` | ≥ 8.2.0 | Test runner |
| `pytest-asyncio` | ≥ 0.23.0 | Async test support |
| `pytest-cov` | ≥ 5.0.0 | Branch coverage enforcement |
