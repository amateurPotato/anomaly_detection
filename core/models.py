from __future__ import annotations

import time
from typing import List

from pydantic import BaseModel, Field, field_validator
from pydantic.networks import IPvAnyAddress


class Event(BaseModel):
    """A single network log entry from the telemetry firehose."""

    source_ip: str
    endpoint: str
    payload_size: int
    timestamp: float = Field(default_factory=time.time)

    @field_validator("payload_size")
    @classmethod
    def payload_must_be_non_negative(cls, v: int) -> int:
        if v < 0:
            raise ValueError("payload_size must be non-negative")
        return v

    @field_validator("source_ip")
    @classmethod
    def source_ip_must_be_valid(cls, v: str) -> str:
        try:
            IPvAnyAddress(v)
        except ValueError:
            raise ValueError(f"Invalid IP address: {v!r}")
        return v

    @field_validator("endpoint")
    @classmethod
    def endpoint_must_not_be_empty(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("endpoint must not be empty")
        return v


class IPContext(BaseModel):
    """
    Aggregated context for a specific source_ip to be passed to the LLM.
    Produced by AnomalyTracker when a rule threshold is breached.
    """

    source_ip: str
    unique_endpoints: List[str]
    total_payload_size: int
    event_count: int
    window_start: float
    window_end: float
    triggered_rules: List[str]


class LLMAnalysis(BaseModel):
    """
    Structured output from Claude's forced tool-use call.
    Represents the reasoning chain: score + observations + mitigation.
    """

    threat_score: float = Field(
        ge=0.0,
        le=1.0,
        description="Probability this is malicious activity (0.0 = benign, 1.0 = confirmed threat)",
    )
    observations: List[str] = Field(
        min_length=1,
        description="Specific observations explaining the reasoning",
    )
    suggested_mitigation: str = Field(
        min_length=1,
        description="Concrete recommended action",
    )


class AnomalyReport(BaseModel):
    """Final combined record: triggering context + LLM verdict."""

    context: IPContext
    analysis: LLMAnalysis
    reported_at: float = Field(default_factory=time.time)
    batch_id: str


class TrackerConfig(BaseModel):
    """Dependency-injected configuration for AnomalyTracker."""

    window_seconds: int = 60
    unique_endpoint_threshold: int = 10
    payload_threshold_bytes: int = 10 * 1024 * 1024  # 10 MB
    micro_batch_seconds: float = 10.0
    max_queue_size: int = 10_000
    stale_window_seconds: int = 300  # 5 minutes
    circuit_breaker_threshold: int = 5   # consecutive failures before opening
    circuit_breaker_cooldown_seconds: float = 60.0  # seconds to stay open

    # Hybrid LLM: False = local Ollama (default), True = cloud Anthropic
    use_cloud_llm: bool = False
    ollama_model: str = "llama3.2"
    ollama_base_url: str = "http://localhost:11434"
