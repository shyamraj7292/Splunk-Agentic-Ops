#!/usr/bin/env python
"""CLI demo runner for the Sentinel triage agent.

Examples
--------
List the bundled scenarios::

    python scripts/run_demo.py --list

Run a single scenario and watch the live investigation trace::

    python scripts/run_demo.py --scenario powershell_encoded_cmd

Run every scenario and save Markdown reports::

    python scripts/run_demo.py --all --save-dir reports
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path

# Allow running this script directly (``python scripts/run_demo.py``) as well
# as via ``python -m``.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

if sys.stdout.encoding and sys.stdout.encoding.lower() != "utf-8":
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stderr.reconfigure(encoding="utf-8")

from agent.config import get_config  # noqa: E402
from agent.report import report_to_markdown  # noqa: E402
from agent.scenarios import Scenario, get_scenario, list_scenarios  # noqa: E402
from agent.triage_agent import TriageAgent  # noqa: E402

try:
    from rich.console import Console
    from rich.json import JSON
    from rich.panel import Panel
    from rich.rule import Rule
    from rich.table import Table

    HAS_RICH = True
except ImportError:  # pragma: no cover - degrade gracefully
    HAS_RICH = False


VERDICT_STYLE = {
    "true_positive": "bold red",
    "escalate": "bold yellow",
    "false_positive": "bold green",
}


def _short_json(data, limit: int = 600) -> str:
    text = json.dumps(data, default=str)
    return text if len(text) <= limit else text[: limit - 3] + "..."


# ---------------------------------------------------------------------------
# Rich rendering
# ---------------------------------------------------------------------------


def _render_event_rich(console: "Console", event) -> None:
    if event.type == "start":
        console.print(Rule(str(event.content), style="cyan"))
    elif event.type == "thought":
        step = f" (step {event.step})" if event.step else ""
        console.print(f"[bold cyan]Thought{step}[/bold cyan]")
        console.print(f"  {event.content}")
    elif event.type == "action":
        console.print(
            f"[bold yellow]Action[/bold yellow]  "
            f"[white]{event.tool}[/white]({_short_json(event.arguments, 200)})"
        )
    elif event.type == "observation":
        tags = ""
        if event.indicator_tags:
            tags = "  [magenta]indicators: " + ", ".join(event.indicator_tags) + "[/magenta]"
        console.print(f"[bold green]Observation[/bold green]  {event.title}{tags}")
        console.print(JSON(json.dumps(event.data, default=str)), no_wrap=False)
    elif event.type == "verdict":
        _render_report_rich(console, event.content)
    console.print()


def _render_report_rich(console: "Console", report: dict) -> None:
    v = report["verdict"]
    style = VERDICT_STYLE.get(v["verdict"], "bold white")
    header = f"{v['verdict'].upper().replace('_', ' ')}  |  severity={v['severity'].upper()}  |  confidence={v['confidence']:.0%}"
    console.print(Panel(f"[{style}]{header}[/{style}]\n\n{v['narrative']}", title="VERDICT", border_style=style.split()[-1]))

    if v["mitre_techniques"]:
        table = Table(title="MITRE ATT&CK Techniques")
        table.add_column("ID")
        table.add_column("Name")
        table.add_column("Tactic")
        for t in v["mitre_techniques"]:
            table.add_row(t["id"], t["name"], t["tactic"])
        console.print(table)

    if v["recommended_actions"]:
        console.print("[bold]Recommended Actions:[/bold]")
        for action_text in v["recommended_actions"]:
            console.print(f"  - {action_text}")


# ---------------------------------------------------------------------------
# Plain-text rendering (no rich installed)
# ---------------------------------------------------------------------------


def _render_event_plain(event) -> None:
    if event.type == "start":
        print(f"\n=== {event.content} ===")
    elif event.type == "thought":
        step = f" (step {event.step})" if event.step else ""
        print(f"\nThought{step}: {event.content}")
    elif event.type == "action":
        print(f"Action  : {event.tool}({_short_json(event.arguments, 200)})")
    elif event.type == "observation":
        tags = f"  indicators: {', '.join(event.indicator_tags)}" if event.indicator_tags else ""
        print(f"Observation: {event.title}{tags}")
        print(f"  data: {_short_json(event.data)}")
    elif event.type == "verdict":
        _render_report_plain(event.content)


def _render_report_plain(report: dict) -> None:
    v = report["verdict"]
    print("\n--- VERDICT ---")
    print(f"{v['verdict'].upper()} | severity={v['severity'].upper()} | confidence={v['confidence']:.0%}")
    print(v["narrative"])
    if v["mitre_techniques"]:
        print("\nMITRE ATT&CK Techniques:")
        for t in v["mitre_techniques"]:
            print(f"  {t['id']:<12} {t['name']} [{t['tactic']}]")
    if v["recommended_actions"]:
        print("\nRecommended Actions:")
        for action_text in v["recommended_actions"]:
            print(f"  - {action_text}")


# ---------------------------------------------------------------------------
# Driver
# ---------------------------------------------------------------------------


async def run_scenario(scenario: Scenario, console: "Console | None", save_dir: Path | None) -> dict:
    config = get_config()
    agent = TriageAgent(config, scenario)

    report: dict | None = None
    async for event in agent.investigate():
        if console is not None:
            _render_event_rich(console, event)
        else:
            _render_event_plain(event)
        if event.type == "verdict":
            report = event.content

    assert report is not None
    if save_dir is not None:
        save_dir.mkdir(parents=True, exist_ok=True)
        out_path = save_dir / f"{scenario.id}.md"
        out_path.write_text(report_to_markdown(report), encoding="utf-8")
        if console is not None:
            console.print(f"[dim]Saved report to {out_path}[/dim]")
        else:
            print(f"Saved report to {out_path}")
    return report


async def main_async(args: argparse.Namespace) -> int:
    console = Console() if HAS_RICH and not args.no_rich else None

    if args.list:
        for scenario in list_scenarios():
            print(f"{scenario.id:<32} [{scenario.category}] {scenario.title}")
        return 0

    save_dir = Path(args.save_dir) if args.save_dir else None

    if args.all:
        scenarios = list_scenarios()
    elif args.scenario:
        try:
            scenarios = [get_scenario(args.scenario)]
        except KeyError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
    else:
        scenarios = list_scenarios()  # default: run everything

    for scenario in scenarios:
        if console is not None:
            console.print(Rule(f"[bold white]{scenario.title}[/bold white] [dim]({scenario.id})[/dim]", style="blue"))
        else:
            print(f"\n##### {scenario.title} ({scenario.id}) #####")
        await run_scenario(scenario, console, save_dir)

    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--scenario", help="Run a single scenario by id")
    parser.add_argument("--all", action="store_true", help="Run all bundled scenarios")
    parser.add_argument("--list", action="store_true", help="List available scenarios and exit")
    parser.add_argument("--save-dir", help="Directory to save Markdown reports into")
    parser.add_argument("--no-rich", action="store_true", help="Disable rich formatting (plain text output)")
    args = parser.parse_args()
    return asyncio.run(main_async(args))


if __name__ == "__main__":
    raise SystemExit(main())
