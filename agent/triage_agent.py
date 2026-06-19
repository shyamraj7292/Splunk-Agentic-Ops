"""The core ReAct-style investigation loop.

:class:`TriageAgent` repeatedly asks its reasoning backend (Foundation-sec,
Claude, or the offline simulated reasoner) what to do next, executes that
action against the Splunk MCP Server (or its offline mock), and feeds the
observation back in - until the backend decides it has enough evidence, or
``AGENT_MAX_STEPS`` is reached. Every step is yielded as a :class:`TraceEvent`
so callers (the CLI and the web UI) can render the investigation live.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import AsyncIterator

from .config import Config
from .llm_client import LLMClient, get_llm_client
from .mcp_client import SplunkMCPClient
from .mitre_mapping import map_indicators_to_techniques
from .report import InvestigationReport, TraceEvent
from .scenarios import Scenario

__all__ = ["TriageAgent"]


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _merge_techniques(primary: list[dict], baseline: list[dict]) -> list[dict]:
    """Combine the LLM's cited techniques with the indicator-tag baseline.

    The baseline (derived from which evidence steps were actually retrieved)
    fills in anything the model missed; the model's own entries take
    precedence when both describe the same technique ID.
    """

    merged: dict[str, dict] = {}
    for technique in baseline:
        merged[technique["id"]] = technique
    for technique in primary:
        if technique.get("id"):
            merged[technique["id"]] = technique
    return [merged[key] for key in sorted(merged)]


class TriageAgent:
    """Runs a single end-to-end investigation for one scenario/alert."""

    def __init__(self, config: Config, scenario: Scenario, llm: LLMClient | None = None):
        self.config = config
        self.scenario = scenario
        self.llm = llm or get_llm_client(config, scenario)

    async def investigate(self) -> AsyncIterator[TraceEvent]:
        """Yield :class:`TraceEvent`s as the investigation proceeds.

        The final event has ``type="verdict"`` and its ``content`` field is
        the full :class:`InvestigationReport`, serialized via ``to_dict()``.
        """

        started_at = _now()
        alert = self.scenario.alert
        history: list[dict] = []
        discovered_tags: list[str] = []
        max_steps = self.config.agent_max_steps

        yield TraceEvent(
            type="start",
            timestamp=_now(),
            content=f"Investigation started for '{alert.get('rule_name', 'alert')}' using {self.llm.name}.",
        )

        async with SplunkMCPClient(self.config, self.scenario) as client:
            tools = await client.list_tools()
            step_num = 0

            while step_num < max_steps:
                step_num += 1
                action = await self.llm.decide_next_action(alert, history, tools)

                yield TraceEvent(type="thought", timestamp=_now(), step=step_num, content=action.thought)

                if action.action == "finalize" or not action.tool_name:
                    break

                yield TraceEvent(
                    type="action",
                    timestamp=_now(),
                    step=step_num,
                    tool=action.tool_name,
                    arguments=action.tool_arguments,
                )

                result = await client.call_tool(action.tool_name, action.tool_arguments)

                for tag in result.indicator_tags:
                    if tag not in discovered_tags:
                        discovered_tags.append(tag)

                history.append(
                    {
                        "tool": result.tool,
                        "arguments": result.arguments,
                        "title": result.title,
                        "data": result.data,
                        "indicator_tags": result.indicator_tags,
                    }
                )

                yield TraceEvent(
                    type="observation",
                    timestamp=_now(),
                    step=step_num,
                    tool=result.tool,
                    title=result.title,
                    data=result.data,
                    indicator_tags=result.indicator_tags,
                )
            else:
                yield TraceEvent(
                    type="thought",
                    timestamp=_now(),
                    content=(
                        f"Reached the maximum of {max_steps} investigation steps - "
                        "finalizing with the evidence gathered so far."
                    ),
                )

            verdict = await self.llm.finalize_verdict(alert, history)

        baseline_techniques = map_indicators_to_techniques(discovered_tags)
        verdict.mitre_techniques = _merge_techniques(verdict.mitre_techniques, baseline_techniques)

        finished_at = _now()
        report = InvestigationReport(
            scenario_id=self.scenario.id,
            alert=alert,
            backend_name=self.llm.name,
            started_at=started_at,
            finished_at=finished_at,
            evidence_log=history,
            verdict=verdict,
            discovered_indicator_tags=discovered_tags,
        )

        yield TraceEvent(type="verdict", timestamp=finished_at, verdict=verdict.to_dict(), content=report.to_dict())
