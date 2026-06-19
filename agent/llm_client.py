"""Reasoning backends for the triage agent.

Three interchangeable backends implement the same tiny interface
(:meth:`decide_next_action` / :meth:`finalize_verdict`). :func:`get_llm_client`
picks one based on configuration, first match wins:

1. ``FOUNDATION_SEC_BASE_URL`` set  -> :class:`FoundationSecClient`
   (Splunk's hosted, security-tuned Foundation-sec model via an
   OpenAI-compatible endpoint - this is the "Best Use of Hosted Models" path)
2. ``ANTHROPIC_API_KEY`` set        -> :class:`AnthropicClient` (fallback reasoning)
3. neither set                      -> :class:`SimulatedReasoningClient`
   (deterministic, scenario-aware - runs the full demo with zero API keys)
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any, Protocol

from .config import Config
from .mitre_mapping import TECHNIQUES
from .scenarios import Scenario, ScenarioStep

__all__ = [
    "AgentAction",
    "Verdict",
    "LLMClient",
    "FoundationSecClient",
    "AnthropicClient",
    "SimulatedReasoningClient",
    "get_llm_client",
]


# ---------------------------------------------------------------------------
# Shared data contracts
# ---------------------------------------------------------------------------


@dataclass
class AgentAction:
    """The agent's decision at one ReAct step."""

    thought: str
    action: str  # "tool_call" | "finalize"
    tool_name: str | None = None
    tool_arguments: dict[str, Any] = field(default_factory=dict)


@dataclass
class Verdict:
    """The agent's final, structured investigation outcome."""

    verdict: str  # "true_positive" | "false_positive" | "escalate"
    severity: str  # "low" | "medium" | "high" | "critical"
    confidence: float
    mitre_techniques: list[dict[str, str]]
    narrative: str
    recommended_actions: list[str]

    def to_dict(self) -> dict[str, Any]:
        return {
            "verdict": self.verdict,
            "severity": self.severity,
            "confidence": self.confidence,
            "mitre_techniques": self.mitre_techniques,
            "narrative": self.narrative,
            "recommended_actions": self.recommended_actions,
        }


class LLMClient(Protocol):
    """Interface implemented by every reasoning backend."""

    name: str

    async def decide_next_action(
        self, alert: dict[str, Any], history: list[dict[str, Any]], tools: list[dict[str, Any]]
    ) -> AgentAction: ...

    async def finalize_verdict(
        self, alert: dict[str, Any], evidence_log: list[dict[str, Any]]
    ) -> Verdict: ...


# ---------------------------------------------------------------------------
# Prompting helpers shared by the real-model backends
# ---------------------------------------------------------------------------

_ACTION_SYSTEM_TEMPLATE = """You are Sentinel, an autonomous SOC Tier-1 triage analyst.
You investigate a single Splunk notable event by calling tools to gather evidence,
then render a verdict. Work step by step like an experienced analyst: form a
hypothesis, gather the evidence that would confirm or refute it, and stop once
you have enough to justify a verdict (typically 3-6 tool calls).

Available tools:
{tool_lines}

At every step, respond with ONLY a single JSON object (no markdown fences, no
extra text) of the form:
{{"thought": "<your reasoning for this step>", "action": "tool_call" | "finalize", "tool_name": "<tool name, if action=tool_call>", "tool_arguments": {{...}}}}

Call "finalize" once you have sufficient evidence to render a verdict, or once
you have made {max_steps} tool calls."""

_VERDICT_SYSTEM = """You are Sentinel, an autonomous SOC Tier-1 triage analyst.
You have finished gathering evidence for a Splunk notable event. Render your
final verdict as ONLY a single JSON object (no markdown fences, no extra text)
of the form:
{"verdict": "true_positive" | "false_positive" | "escalate",
 "severity": "low" | "medium" | "high" | "critical",
 "confidence": <number between 0 and 1>,
 "mitre_techniques": [{"id": "T####(.###)", "name": "<technique name>", "tactic": "<tactic>"}],
 "narrative": "<2-5 sentence plain-English summary of what happened and why it matters>",
 "recommended_actions": ["<concrete next step>", "..."]}

Base the verdict strictly on the evidence gathered. Cite specific hosts,
users, IPs, domains, and timestamps from the evidence in your narrative."""


def _tool_lines(tools: list[dict[str, Any]]) -> str:
    return "\n".join(f"- {t['name']}: {t['description']}" for t in tools)


def _format_alert(alert: dict[str, Any]) -> str:
    return json.dumps(alert, indent=2, default=str)


def _format_history(history: list[dict[str, Any]]) -> str:
    if not history:
        return "(no evidence gathered yet - this is the first step)"
    blocks = []
    for i, item in enumerate(history, 1):
        data_str = json.dumps(item.get("data"), default=str)
        if len(data_str) > 1500:
            data_str = data_str[:1500] + "... (truncated)"
        blocks.append(
            f"Step {i}: {item.get('tool')}({json.dumps(item.get('arguments'), default=str)})\n"
            f"  -> {data_str}"
        )
    return "\n".join(blocks)


def _action_messages(
    alert: dict[str, Any], history: list[dict[str, Any]], tools: list[dict[str, Any]], max_steps: int
) -> tuple[str, str]:
    system = _ACTION_SYSTEM_TEMPLATE.format(tool_lines=_tool_lines(tools), max_steps=max_steps)
    user = (
        f"ALERT:\n{_format_alert(alert)}\n\n"
        f"EVIDENCE GATHERED SO FAR:\n{_format_history(history)}\n\n"
        "What is your next action?"
    )
    return system, user


def _verdict_messages(alert: dict[str, Any], evidence_log: list[dict[str, Any]]) -> tuple[str, str]:
    user = (
        f"ALERT:\n{_format_alert(alert)}\n\n"
        f"FULL EVIDENCE LOG:\n{_format_history(evidence_log)}\n\n"
        "Render your final verdict now."
    )
    return _VERDICT_SYSTEM, user


_JSON_OBJECT_RE = re.compile(r"\{.*\}", re.DOTALL)


def _extract_json(text: str) -> dict[str, Any] | None:
    """Best-effort extraction of a JSON object from a model response."""

    text = text.strip()
    text = re.sub(r"^```(?:json)?\s*|\s*```$", "", text.strip(), flags=re.MULTILINE).strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass

    match = _JSON_OBJECT_RE.search(text)
    if match:
        try:
            return json.loads(match.group(0))
        except json.JSONDecodeError:
            return None
    return None


def _attack_url(technique_id: str) -> str:
    known = TECHNIQUES.get(technique_id)
    if known:
        return known.url
    base_id = technique_id.split(".")[0]
    if "." in technique_id:
        sub_id = technique_id.split(".")[1]
        return f"https://attack.mitre.org/techniques/{base_id}/{sub_id}/"
    return f"https://attack.mitre.org/techniques/{base_id}/"


def _parse_action(text: str) -> AgentAction:
    data = _extract_json(text)
    if not data:
        return AgentAction(
            thought=text.strip()[:500] or "Reviewing the evidence gathered so far.",
            action="finalize",
        )

    action = data.get("action", "finalize")
    if action not in ("tool_call", "finalize"):
        action = "finalize"

    return AgentAction(
        thought=str(data.get("thought", "")).strip() or "Continuing the investigation.",
        action=action,
        tool_name=data.get("tool_name"),
        tool_arguments=data.get("tool_arguments") or {},
    )


def _parse_verdict(text: str) -> Verdict:
    data = _extract_json(text)
    if not data:
        return Verdict(
            verdict="escalate",
            severity="medium",
            confidence=0.3,
            mitre_techniques=[],
            narrative=(
                "The reasoning model returned a response that could not be parsed as a "
                "structured verdict. Escalating to a human analyst for manual review. "
                f"Raw model output: {text.strip()[:500]}"
            ),
            recommended_actions=["Escalate to a human analyst - automated verdict parsing failed."],
        )

    raw_techniques = data.get("mitre_techniques") or []
    techniques: list[dict[str, str]] = []
    for t in raw_techniques:
        if isinstance(t, dict) and t.get("id"):
            techniques.append(
                {
                    "id": str(t["id"]),
                    "name": str(t.get("name", "")),
                    "tactic": str(t.get("tactic", "")),
                    "url": str(t.get("url") or _attack_url(str(t["id"]))),
                }
            )

    try:
        confidence = float(data.get("confidence", 0.5))
    except (TypeError, ValueError):
        confidence = 0.5
    confidence = max(0.0, min(1.0, confidence))

    return Verdict(
        verdict=str(data.get("verdict", "escalate")),
        severity=str(data.get("severity", "medium")),
        confidence=confidence,
        mitre_techniques=techniques,
        narrative=str(data.get("narrative", "")).strip(),
        recommended_actions=[str(a) for a in (data.get("recommended_actions") or [])],
    )


# ---------------------------------------------------------------------------
# Foundation-sec (Splunk hosted model, OpenAI-compatible endpoint)
# ---------------------------------------------------------------------------


class FoundationSecClient:
    """Splunk's hosted Foundation-sec model via an OpenAI-compatible API.

    This is the path that earns "Best Use of Hosted Models": Foundation-sec
    is a security-tuned model Splunk hosts so teams get a SOC-aware reasoning
    engine with zero ML infrastructure.
    """

    name = "Splunk Foundation-sec (hosted model)"

    def __init__(self, config: Config):
        try:
            from openai import AsyncOpenAI
        except ImportError as exc:  # pragma: no cover - optional dependency
            raise RuntimeError(
                "FOUNDATION_SEC_BASE_URL is set but the 'openai' package is not "
                "installed. Install it with 'pip install openai'."
            ) from exc

        self._client = AsyncOpenAI(
            base_url=config.llm.foundation_sec_base_url,
            api_key=config.llm.foundation_sec_api_key or "not-required",
        )
        self._model = config.llm.foundation_sec_model
        self._max_steps = config.agent_max_steps

    async def decide_next_action(self, alert, history, tools) -> AgentAction:
        system, user = _action_messages(alert, history, tools, self._max_steps)
        response = await self._client.chat.completions.create(
            model=self._model,
            messages=[{"role": "system", "content": system}, {"role": "user", "content": user}],
            temperature=0.1,
            max_tokens=700,
        )
        return _parse_action(response.choices[0].message.content or "")

    async def finalize_verdict(self, alert, evidence_log) -> Verdict:
        system, user = _verdict_messages(alert, evidence_log)
        response = await self._client.chat.completions.create(
            model=self._model,
            messages=[{"role": "system", "content": system}, {"role": "user", "content": user}],
            temperature=0.1,
            max_tokens=1200,
        )
        return _parse_verdict(response.choices[0].message.content or "")


# ---------------------------------------------------------------------------
# Anthropic Claude (fallback reasoning backend)
# ---------------------------------------------------------------------------


class AnthropicClient:
    """Anthropic Claude as a fallback reasoning backend."""

    name = "Anthropic Claude"

    def __init__(self, config: Config):
        try:
            import anthropic
        except ImportError as exc:  # pragma: no cover - optional dependency
            raise RuntimeError(
                "ANTHROPIC_API_KEY is set but the 'anthropic' package is not "
                "installed. Install it with 'pip install anthropic'."
            ) from exc

        self._client = anthropic.AsyncAnthropic(api_key=config.llm.anthropic_api_key)
        self._model = config.llm.anthropic_model
        self._max_steps = config.agent_max_steps

    async def _complete(self, system: str, user: str, max_tokens: int) -> str:
        response = await self._client.messages.create(
            model=self._model,
            max_tokens=max_tokens,
            system=system,
            messages=[{"role": "user", "content": user}],
        )
        return "".join(block.text for block in response.content if hasattr(block, "text"))

    async def decide_next_action(self, alert, history, tools) -> AgentAction:
        system, user = _action_messages(alert, history, tools, self._max_steps)
        text = await self._complete(system, user, max_tokens=700)
        return _parse_action(text)

    async def finalize_verdict(self, alert, evidence_log) -> Verdict:
        system, user = _verdict_messages(alert, evidence_log)
        text = await self._complete(system, user, max_tokens=1500)
        return _parse_verdict(text)


# ---------------------------------------------------------------------------
# Simulated reasoning (offline, zero-config demo backend)
# ---------------------------------------------------------------------------


def _step_tool_arguments(step: ScenarioStep) -> dict[str, Any]:
    """Build plausible tool arguments for a scenario step.

    The arguments are crafted so :class:`agent.mock_backend.MockSplunkBackend`
    matches this exact step (its ``match_any`` keywords appear in the values),
    keeping the simulated trace and the underlying data in lockstep.
    """

    if step.tool == "splunk_search":
        return {"query": step.spl or step.title, "earliest_time": "-24h", "latest_time": "now"}
    if step.tool == "saia_generate_spl":
        return {"question": step.title}
    if step.tool == "saia_explain_spl":
        return {"spl": step.spl or ""}
    if step.tool in ("get_asset_context", "get_identity_context"):
        key = "asset" if step.tool == "get_asset_context" else "user"
        value = step.match_any[0] if step.match_any else ""
        return {key: value}
    return {}


_OPENING_TEMPLATES = [
    "New alert: {description} Let's start by {action}.",
]
_CONTINUATION_TEMPLATES = [
    "That confirms {prev_title_lower}. Next I should {action} to follow this thread.",
    "Building on that finding, I'll now {action}.",
    "Given what we just saw, the natural next step is to {action}.",
]
_FINAL_STEP_TEMPLATES = [
    "This should round out the picture - one last check: {action}.",
]


def _lowercase_first(text: str) -> str:
    return text[0].lower() + text[1:] if text else text


class SimulatedReasoningClient:
    """Deterministic, scenario-aware reasoning - no API keys required.

    Walks the scenario's evidence steps in narrative order, producing
    analyst-style "thoughts" for each tool call, then returns the
    scenario's expert-authored verdict as ground truth. This guarantees the
    full demo (CLI and web UI) works with zero configuration and zero
    external API calls.
    """

    name = "Simulated Reasoning (offline demo - no API key required)"

    def __init__(self, scenario: Scenario):
        self.scenario = scenario
        self._next_index = 0

    async def decide_next_action(self, alert, history, tools) -> AgentAction:
        steps = self.scenario.steps
        if self._next_index >= len(steps):
            return AgentAction(
                thought=(
                    "I've gathered enough evidence to correlate the initial trigger with "
                    "its root cause, blast radius, and business context. Time to render a verdict."
                ),
                action="finalize",
            )

        step = steps[self._next_index]
        is_first = self._next_index == 0
        is_last = self._next_index == len(steps) - 1
        action_phrase = _lowercase_first(step.title)

        if is_first:
            thought = _OPENING_TEMPLATES[0].format(
                description=alert.get("description", "a new notable event was triggered."),
                action=action_phrase,
            )
        elif is_last:
            thought = _FINAL_STEP_TEMPLATES[0].format(action=action_phrase)
        else:
            prev_title = steps[self._next_index - 1].title
            template = _CONTINUATION_TEMPLATES[(self._next_index - 1) % len(_CONTINUATION_TEMPLATES)]
            thought = template.format(prev_title_lower=_lowercase_first(prev_title), action=action_phrase)

        self._next_index += 1
        return AgentAction(
            thought=thought,
            action="tool_call",
            tool_name=step.tool,
            tool_arguments=_step_tool_arguments(step),
        )

    async def finalize_verdict(self, alert, evidence_log) -> Verdict:
        from .mitre_mapping import map_indicators_to_techniques

        gt = self.scenario.ground_truth
        techniques = map_indicators_to_techniques(gt.get("mitre_indicator_tags", []))
        return Verdict(
            verdict=gt["verdict"],
            severity=gt["severity"],
            confidence=float(gt["confidence"]),
            mitre_techniques=techniques,
            narrative=gt["narrative"],
            recommended_actions=list(gt["recommended_actions"]),
        )


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------


def get_llm_client(config: Config, scenario: Scenario | None = None) -> LLMClient:
    """Return the configured reasoning backend, first match wins."""

    if config.llm.foundation_sec_base_url:
        return FoundationSecClient(config)
    if config.llm.anthropic_api_key:
        return AnthropicClient(config)
    if scenario is not None:
        return SimulatedReasoningClient(scenario)
    raise RuntimeError(
        "No LLM backend configured. Set FOUNDATION_SEC_BASE_URL (Splunk "
        "Foundation-sec) or ANTHROPIC_API_KEY for live mode, or use "
        "SPLUNK_MODE=mock to run the offline simulated-reasoning demo."
    )
