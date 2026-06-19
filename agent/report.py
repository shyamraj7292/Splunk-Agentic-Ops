"""Data models for investigation traces and final reports."""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Any

from .llm_client import Verdict

__all__ = ["TraceEvent", "InvestigationReport", "report_to_markdown"]


_VERDICT_LABELS = {
    "true_positive": "TRUE POSITIVE",
    "false_positive": "FALSE POSITIVE",
    "escalate": "ESCALATE",
}

_SEVERITY_EMOJI = {
    "critical": "\U0001F534",  # red circle
    "high": "\U0001F7E0",  # orange circle
    "medium": "\U0001F7E1",  # yellow circle
    "low": "\U0001F7E2",  # green circle
}


@dataclass
class TraceEvent:
    """A single step in the agent's investigation, streamed to the UI/CLI."""

    type: str  # "start" | "thought" | "action" | "observation" | "verdict" | "error"
    timestamp: str
    step: int | None = None
    content: Any = None
    tool: str | None = None
    arguments: dict[str, Any] | None = None
    title: str | None = None
    data: Any = None
    indicator_tags: list[str] = field(default_factory=list)
    verdict: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        return {k: v for k, v in asdict(self).items() if v is not None and v != []}


@dataclass
class InvestigationReport:
    """The final, structured output of an investigation."""

    scenario_id: str | None
    alert: dict[str, Any]
    backend_name: str
    started_at: str
    finished_at: str
    evidence_log: list[dict[str, Any]]
    verdict: Verdict
    discovered_indicator_tags: list[str]

    def to_dict(self) -> dict[str, Any]:
        return {
            "scenario_id": self.scenario_id,
            "alert": self.alert,
            "backend_name": self.backend_name,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "evidence_log": self.evidence_log,
            "verdict": self.verdict.to_dict(),
            "discovered_indicator_tags": self.discovered_indicator_tags,
        }

    def to_markdown(self) -> str:
        return report_to_markdown(self.to_dict())


def report_to_markdown(report: dict[str, Any]) -> str:
    """Render an :class:`InvestigationReport` (as produced by ``to_dict()``) as Markdown.

    Operates on the plain-dict form so callers that only have the
    serialized report (e.g. the CLI consuming a streamed ``verdict``
    :class:`TraceEvent`) can render it without reconstructing dataclasses.
    """

    verdict = report["verdict"]
    alert = report["alert"]

    verdict_label = _VERDICT_LABELS.get(verdict["verdict"], verdict["verdict"].upper())
    severity_emoji = _SEVERITY_EMOJI.get(verdict["severity"].lower(), "⚪")

    lines: list[str] = []
    lines.append(f"# Investigation Report: {alert.get('rule_name', 'Unknown Alert')}")
    lines.append("")
    lines.append(f"**Verdict:** {verdict_label}")
    lines.append(f"**Severity:** {severity_emoji} {verdict['severity'].upper()}")
    lines.append(f"**Confidence:** {verdict['confidence']:.0%}")
    lines.append(f"**Reasoning engine:** {report['backend_name']}")
    lines.append(f"**Investigation window:** {report['started_at']} -> {report['finished_at']}")
    lines.append("")

    lines.append("## Alert")
    for key in ("host", "user", "src_ip", "dest_domain", "time", "severity", "source"):
        if key in alert:
            lines.append(f"- **{key}**: {alert[key]}")
    if "description" in alert:
        lines.append("")
        lines.append(alert["description"])
    lines.append("")

    lines.append("## Narrative")
    lines.append(verdict["narrative"])
    lines.append("")

    if verdict["mitre_techniques"]:
        lines.append("## MITRE ATT&CK Techniques")
        lines.append("| ID | Name | Tactic |")
        lines.append("|----|------|--------|")
        for t in verdict["mitre_techniques"]:
            lines.append(f"| [{t['id']}]({t.get('url', '')}) | {t['name']} | {t['tactic']} |")
        lines.append("")

    if verdict["recommended_actions"]:
        lines.append("## Recommended Actions")
        for action_text in verdict["recommended_actions"]:
            lines.append(f"- [ ] {action_text}")
        lines.append("")

    if report["evidence_log"]:
        lines.append("## Evidence Log")
        for i, entry in enumerate(report["evidence_log"], 1):
            lines.append(f"{i}. **{entry['tool']}** - {entry['title']}")
            if entry.get("indicator_tags"):
                tags = ", ".join(f"`{t}`" for t in entry["indicator_tags"])
                lines.append(f"   - Indicators: {tags}")
        lines.append("")

    return "\n".join(lines)
