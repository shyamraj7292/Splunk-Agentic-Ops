"""Loader for the bundled BOTS-inspired investigation scenarios.

Each scenario lives as a JSON file under ``data/scenarios/`` and describes:

* ``alert``        - the notable event / alert that triggers an investigation
* ``steps``        - canned evidence the mock Splunk backend can return,
                      each tagged with the indicator(s) it reveals
* ``ground_truth`` - the "answer key": verdict, severity, confidence,
                      narrative and recommended actions an expert analyst
                      would produce, used by the simulated reasoning
                      backend and as a reference for live LLM output.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

SCENARIOS_DIR = Path(__file__).resolve().parent.parent / "data" / "scenarios"


@dataclass(frozen=True)
class ScenarioStep:
    step: int
    tool: str
    title: str
    match_any: list[str]
    result: Any
    indicator_tags: list[str] = field(default_factory=list)
    spl: str | None = None


@dataclass(frozen=True)
class Scenario:
    id: str
    title: str
    category: str
    short_description: str
    alert: dict
    steps: list[ScenarioStep]
    ground_truth: dict

    @property
    def step_count(self) -> int:
        return len(self.steps)


def _load(path: Path) -> Scenario:
    data = json.loads(path.read_text(encoding="utf-8"))
    steps = [
        ScenarioStep(
            step=s["step"],
            tool=s["tool"],
            title=s["title"],
            match_any=[m.lower() for m in s.get("match_any", [])],
            result=s["result"],
            indicator_tags=s.get("indicator_tags", []),
            spl=s.get("spl"),
        )
        for s in data["steps"]
    ]
    return Scenario(
        id=data["id"],
        title=data["title"],
        category=data["category"],
        short_description=data["short_description"],
        alert=data["alert"],
        steps=steps,
        ground_truth=data["ground_truth"],
    )


_CACHE: dict[str, Scenario] | None = None


def _load_all() -> dict[str, Scenario]:
    global _CACHE
    if _CACHE is None:
        cache: dict[str, Scenario] = {}
        for path in sorted(SCENARIOS_DIR.glob("*.json")):
            scenario = _load(path)
            cache[scenario.id] = scenario
        _CACHE = cache
    return _CACHE


def list_scenarios() -> list[Scenario]:
    """Return all bundled scenarios, in file order."""

    return list(_load_all().values())


def get_scenario(scenario_id: str) -> Scenario:
    """Return a single scenario by id, raising ``KeyError`` if unknown."""

    scenarios = _load_all()
    if scenario_id not in scenarios:
        available = ", ".join(scenarios)
        raise KeyError(f"Unknown scenario '{scenario_id}'. Available: {available}")
    return scenarios[scenario_id]
