from __future__ import annotations

import json

import anthropic
import httpx

from ..core.models import IPContext, LLMAnalysis

# ---------------------------------------------------------------------------
# Tool schema registered with Claude to force structured JSON output.
# Mirrors LLMAnalysis exactly so model_validate() acts as the final gate.
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


class LLMAnalyser:
    """
    Neural layer: sends IPContext to Claude and returns a validated LLMAnalysis.

    Isolated from the tracker so the LLM backend (model, prompt, tool schema)
    can be swapped or extended without touching AnomalyTracker.
    """

    DEFAULT_MODEL = "claude-opus-4-6"

    def __init__(
        self,
        client: anthropic.AsyncAnthropic,
        model: str = DEFAULT_MODEL,
    ) -> None:
        self._client = client
        self._model = model

    async def analyse(self, context: IPContext) -> LLMAnalysis:
        """
        Send IPContext to Claude via forced tool-use and return a validated LLMAnalysis.

        Raises
        ------
        ValueError
            If Claude returns no tool_use block.
        pydantic.ValidationError
            If Claude's JSON violates the LLMAnalysis schema (e.g. threat_score > 1.0).
        """
        response = await self._client.messages.create(
            model=self._model,
            max_tokens=1024,
            tools=[ANALYSIS_TOOL_SCHEMA],
            tool_choice={"type": "tool", "name": "report_anomaly_analysis"},
            messages=[{"role": "user", "content": self.build_prompt(context)}],
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

    def build_prompt(self, context: IPContext) -> str:
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


# JSON schema passed to Ollama's structured-output feature (requires Ollama ≥ 0.5.0).
# Using constrained decoding means the model CANNOT produce prose or markdown —
# the response is always a JSON object that exactly matches this shape.
_LOCAL_OUTPUT_SCHEMA = {
    "type": "object",
    "properties": {
        "threat_score": {
            "type": "number",
            "minimum": 0.0,
            "maximum": 1.0,
        },
        "observations": {
            "type": "array",
            "items": {"type": "string"},
            "minItems": 1,
        },
        "suggested_mitigation": {
            "type": "string",
        },
    },
    "required": ["threat_score", "observations", "suggested_mitigation"],
    "additionalProperties": False,
}


class LocalLLMAnalyser:
    """
    Neural layer: sends IPContext to a local Ollama model and returns a validated LLMAnalysis.

    Uses Ollama's structured-output format (JSON schema constrained decoding, Ollama ≥ 0.5.0)
    so the model is physically prevented from producing anything other than the expected JSON.
    Pydantic validation still runs as a final correctness gate.
    """

    DEFAULT_MODEL = "llama3"

    def __init__(
        self,
        base_url: str = "http://localhost:11434",
        model: str = DEFAULT_MODEL,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._model = model

    async def analyse(self, context: IPContext) -> LLMAnalysis:
        """
        Send IPContext to the local Ollama model and return a validated LLMAnalysis.

        Raises
        ------
        httpx.HTTPError
            If the Ollama server is unreachable or returns a non-2xx status.
        json.JSONDecodeError
            If the model response is not valid JSON (should not happen with schema mode).
        pydantic.ValidationError
            If the JSON does not satisfy the LLMAnalysis field constraints.
        """
        async with httpx.AsyncClient(timeout=120.0) as client:
            response = await client.post(
                f"{self._base_url}/api/chat",
                json={
                    "model": self._model,
                    "messages": [{"role": "user", "content": self.build_prompt(context)}],
                    "format": _LOCAL_OUTPUT_SCHEMA,  # constrained decoding — no chatty prose
                    "stream": False,
                },
            )
            response.raise_for_status()

        data = response.json()
        content = data["message"]["content"]
        parsed = json.loads(content)
        # llama3 ignores schema min/max constraints — clamp to valid range
        if "threat_score" in parsed:
            parsed["threat_score"] = max(0.0, min(1.0, float(parsed["threat_score"])))
        return LLMAnalysis.model_validate(parsed)

    def build_prompt(self, context: IPContext) -> str:
        """
        Focused analysis prompt. Format instructions are omitted — the JSON schema
        passed to Ollama enforces structure, so the prompt concentrates on the task.
        """
        endpoint_list = context.unique_endpoints[:20]
        truncation_note = (
            "...(truncated)" if len(context.unique_endpoints) > 20 else ""
        )
        return (
            f"You are a network security analyst. Classify the suspicious activity below "
            f"as data exfiltration, reconnaissance, or false positive.\n\n"
            f"Source IP         : {context.source_ip}\n"
            f"Triggered rules   : {', '.join(context.triggered_rules)}\n"
            f"Unique endpoints  : {len(context.unique_endpoints)}"
            f" ({', '.join(endpoint_list)}{truncation_note})\n"
            f"Total payload     : {context.total_payload_size:,} bytes\n"
            f"Events in window  : {context.event_count}\n"
            f"Window duration   : {context.window_end - context.window_start:.1f} s\n\n"
            f"Prioritize Lateral Movement indicators: systematic endpoint scanning, "
            f"credential-access staging, east-west traversal."
        )
