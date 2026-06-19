"""Offline simulation of Splunk MCP Server tool calls.

This lets the entire agent run end-to-end with zero infrastructure: no
Splunk instance, no MCP server process, no network access. Each scenario
JSON file under ``data/scenarios/`` ships a small set of "canned" results;
this module matches incoming tool calls against those canned results using
simple keyword scoring, so it behaves reasonably even when a real LLM
(rather than the scripted simulated-reasoning backend) is choosing the
queries.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .scenarios import Scenario, ScenarioStep

# Maps an MCP tool name to the argument key holding its "query text".
# This is the text we score against each scenario step's `match_any` list.
QUERY_ARG_BY_TOOL: dict[str, str] = {
    "splunk_search": "query",
    "saia_generate_spl": "question",
    "saia_explain_spl": "spl",
    "get_asset_context": "asset",
    "get_identity_context": "user",
}


@dataclass
class ToolResult:
    """Normalized result of a tool call, from either the mock or live backend."""

    tool: str
    arguments: dict[str, Any]
    title: str
    data: Any
    indicator_tags: list[str] = field(default_factory=list)
    matched_step: int | None = None


class MockSplunkBackend:
    """Serves canned scenario data in response to MCP-style tool calls."""

    def __init__(self, scenario: Scenario):
        self.scenario = scenario
        self.used_steps: set[int] = set()

    def call_tool(self, name: str, arguments: dict[str, Any]) -> ToolResult:
        arg_key = QUERY_ARG_BY_TOOL.get(name, "query")
        query_text = str(
            arguments.get(arg_key) or " ".join(str(v) for v in arguments.values())
        ).lower()

        candidates = [s for s in self.scenario.steps if s.tool == name]
        if not candidates:
            return ToolResult(
                tool=name,
                arguments=arguments,
                title="No mock data source for this tool",
                data={
                    "note": (
                        f"The mock backend has no canned steps for tool '{name}' "
                        f"in scenario '{self.scenario.id}'."
                    )
                },
            )

        best_step = self._best_match(candidates, query_text)
        is_new = best_step.step not in self.used_steps
        self.used_steps.add(best_step.step)

        return ToolResult(
            tool=name,
            arguments=arguments,
            title=best_step.title,
            data=best_step.result,
            indicator_tags=list(best_step.indicator_tags) if is_new else [],
            matched_step=best_step.step,
        )

    def _best_match(self, candidates: list[ScenarioStep], query_text: str) -> ScenarioStep:
        scored = [
            (sum(1 for kw in step.match_any if kw in query_text), step) for step in candidates
        ]

        unused_scored = [(score, step) for score, step in scored if step.step not in self.used_steps]

        if unused_scored:
            # Prefer the best-scoring step that hasn't been returned yet. A
            # used step can otherwise tie (or even beat) the intended next
            # step on shared keywords, which would re-serve stale data and
            # stall the investigation. If every unused step scores 0 (e.g. a
            # real LLM asked something off-script), fall back to the next
            # one in narrative order so the investigation keeps progressing.
            if any(score > 0 for score, _ in unused_scored):
                unused_scored.sort(key=lambda pair: (-pair[0], pair[1].step))
            else:
                unused_scored.sort(key=lambda pair: pair[1].step)
            return unused_scored[0][1]

        # Every step has already been surfaced - just return the best overall match.
        scored.sort(key=lambda pair: (-pair[0], pair[1].step))
        return scored[0][1]

    def remaining_steps(self) -> list[ScenarioStep]:
        """Steps not yet surfaced to the agent, in narrative order."""

        return [s for s in self.scenario.steps if s.step not in self.used_steps]

    def all_indicator_tags(self) -> list[str]:
        """All indicator tags discovered so far, across used steps."""

        tags: list[str] = []
        for step in self.scenario.steps:
            if step.step in self.used_steps:
                for tag in step.indicator_tags:
                    if tag not in tags:
                        tags.append(tag)
        return tags
