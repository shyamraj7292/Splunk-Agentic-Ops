"""Tests for the Sentinel triage agent core.

Covers scenario loading, MITRE ATT&CK mapping, the offline mock Splunk
backend (including a regression for a step-matching tie-breaking bug), and
a full end-to-end investigation in simulated-reasoning mode for every
bundled scenario.
"""

from __future__ import annotations

import pytest

from agent.config import Config
from agent.llm_client import SimulatedReasoningClient, Verdict
from agent.mitre_mapping import map_indicators_to_techniques
from agent.mock_backend import MockSplunkBackend
from agent.report import report_to_markdown
from agent.scenarios import get_scenario, list_scenarios
from agent.triage_agent import TriageAgent

SCENARIO_IDS = [s.id for s in list_scenarios()]


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------


def test_config_is_mock_property():
    assert Config(splunk_mode="mock").is_mock is True
    assert Config(splunk_mode="MOCK").is_mock is True
    assert Config(splunk_mode="live").is_mock is False


# ---------------------------------------------------------------------------
# Scenario loading
# ---------------------------------------------------------------------------


def test_list_scenarios_returns_all_bundled_scenarios():
    assert set(SCENARIO_IDS) == {
        "powershell_encoded_cmd",
        "brute_force_credential_access",
        "insider_data_staging_exfil",
    }


@pytest.mark.parametrize("scenario_id", SCENARIO_IDS)
def test_get_scenario_round_trips(scenario_id):
    scenario = get_scenario(scenario_id)
    assert scenario.id == scenario_id
    assert scenario.step_count == len(scenario.steps)
    assert scenario.alert["rule_name"]
    assert scenario.ground_truth["verdict"] in {"true_positive", "false_positive", "escalate"}
    assert 0.0 <= scenario.ground_truth["confidence"] <= 1.0


def test_get_scenario_unknown_id_raises_with_available_list():
    with pytest.raises(KeyError) as exc_info:
        get_scenario("does_not_exist")

    message = str(exc_info.value)
    assert "does_not_exist" in message
    for scenario_id in SCENARIO_IDS:
        assert scenario_id in message


# ---------------------------------------------------------------------------
# MITRE ATT&CK mapping
# ---------------------------------------------------------------------------


def test_map_indicators_to_techniques_dedupes_and_sorts():
    techniques = map_indicators_to_techniques(
        ["phishing_attachment", "office_spawned_shell", "phishing_attachment"]
    )
    ids = [t["id"] for t in techniques]

    assert ids == sorted(ids)
    assert len(ids) == len(set(ids))
    assert {"T1566.001", "T1204.002", "T1059.001"}.issubset(set(ids))


def test_map_indicators_to_techniques_ignores_unknown_tags():
    assert map_indicators_to_techniques(["totally_made_up_tag"]) == []


def test_technique_dict_has_mitre_url():
    techniques = map_indicators_to_techniques(["c2_beaconing"])
    assert techniques[0]["id"] == "T1071.001"
    assert techniques[0]["url"] == "https://attack.mitre.org/techniques/T1071/001/"


# ---------------------------------------------------------------------------
# Mock Splunk backend
# ---------------------------------------------------------------------------


def test_mock_backend_serves_matching_step_with_indicator_tags():
    scenario = get_scenario("powershell_encoded_cmd")
    backend = MockSplunkBackend(scenario)

    result = backend.call_tool("splunk_search", {"query": "powershell.exe parentimage winword hoth-fs01"})

    assert result.matched_step == 1
    assert result.indicator_tags == ["office_spawned_shell", "encoded_powershell", "phishing_attachment"]


def test_mock_backend_advances_then_stops_resurfacing_tags():
    """Repeat calls with the same query keep the investigation progressing.

    Once a step has been served, a query that no longer matches any
    *unused* step's keywords advances to the next unused step in narrative
    order (rather than re-serving the used step). Only once every step for
    this tool has been used does the backend fall back to the best overall
    match - at which point its indicator tags are no longer re-surfaced.
    """

    scenario = get_scenario("powershell_encoded_cmd")
    backend = MockSplunkBackend(scenario)
    query = {"query": "powershell.exe parentimage winword hoth-fs01"}

    first = backend.call_tool("splunk_search", query)
    assert first.matched_step == 1
    assert first.indicator_tags == scenario.steps[0].indicator_tags

    second = backend.call_tool("splunk_search", query)
    assert second.matched_step == 3
    assert second.indicator_tags == scenario.steps[2].indicator_tags

    third = backend.call_tool("splunk_search", query)
    assert third.matched_step == 4
    assert third.indicator_tags == scenario.steps[3].indicator_tags

    fourth = backend.call_tool("splunk_search", query)
    assert fourth.matched_step == 1
    assert fourth.indicator_tags == []


def test_mock_backend_resolves_keyword_collision_between_used_and_unused_steps():
    """Regression test for a tie-breaking bug in ``_best_match``.

    Step 3's SPL also contains step 1's ``corp-ws-221`` keyword. After step
    1 has already been served, a query built from step 3's SPL must return
    step 3 (new evidence) rather than re-serving the already-used step 1,
    which previously stalled the investigation.
    """

    scenario = get_scenario("insider_data_staging_exfil")
    backend = MockSplunkBackend(scenario)

    step1, step2, step3 = scenario.steps[0], scenario.steps[1], scenario.steps[2]
    assert "corp-ws-221" in step3.spl.lower()  # shares step1's keyword

    backend.call_tool("splunk_search", {"query": step1.spl})
    backend.call_tool("splunk_search", {"query": step2.spl})

    result = backend.call_tool("splunk_search", {"query": step3.spl})

    assert result.matched_step == 3
    assert result.indicator_tags == step3.indicator_tags


def test_mock_backend_unknown_tool_returns_placeholder():
    scenario = get_scenario("powershell_encoded_cmd")
    backend = MockSplunkBackend(scenario)

    result = backend.call_tool("does_not_exist", {})

    assert result.matched_step is None
    assert result.indicator_tags == []
    assert "does_not_exist" in result.data["note"]


def test_mock_backend_remaining_steps_and_all_indicator_tags():
    scenario = get_scenario("brute_force_credential_access")
    backend = MockSplunkBackend(scenario)

    assert len(backend.remaining_steps()) == scenario.step_count

    backend.call_tool("splunk_search", {"query": scenario.steps[0].spl})

    remaining = backend.remaining_steps()
    assert len(remaining) == scenario.step_count - 1
    assert all(s.step != 1 for s in remaining)
    assert backend.all_indicator_tags() == scenario.steps[0].indicator_tags


# ---------------------------------------------------------------------------
# Full end-to-end investigation (simulated reasoning)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@pytest.mark.parametrize("scenario_id", SCENARIO_IDS)
async def test_simulated_investigation_matches_ground_truth(scenario_id):
    scenario = get_scenario(scenario_id)
    config = Config(splunk_mode="mock", agent_max_steps=scenario.step_count + 1, demo_step_delay_seconds=0.0)
    agent = TriageAgent(config, scenario, llm=SimulatedReasoningClient(scenario))

    events = [event async for event in agent.investigate()]

    assert events[0].type == "start"
    assert events[-1].type == "verdict"

    action_events = [e for e in events if e.type == "action"]
    observation_events = [e for e in events if e.type == "observation"]
    assert len(action_events) == scenario.step_count
    assert len(observation_events) == scenario.step_count
    assert not any(e.type == "error" for e in events)

    report = events[-1].content
    verdict = report["verdict"]
    gt = scenario.ground_truth

    assert verdict["verdict"] == gt["verdict"]
    assert verdict["severity"] == gt["severity"]
    assert verdict["confidence"] == pytest.approx(gt["confidence"])
    assert verdict["narrative"] == gt["narrative"]
    assert verdict["recommended_actions"] == gt["recommended_actions"]

    assert set(report["discovered_indicator_tags"]) == set(gt["mitre_indicator_tags"])
    assert len(report["evidence_log"]) == scenario.step_count

    expected_technique_ids = {t["id"] for t in map_indicators_to_techniques(gt["mitre_indicator_tags"])}
    assert {t["id"] for t in verdict["mitre_techniques"]} == expected_technique_ids
    assert expected_technique_ids  # every bundled scenario maps to at least one technique


# ---------------------------------------------------------------------------
# Markdown report rendering
# ---------------------------------------------------------------------------


def test_report_to_markdown_includes_key_sections():
    scenario = get_scenario("brute_force_credential_access")
    gt = scenario.ground_truth
    verdict = Verdict(
        verdict=gt["verdict"],
        severity=gt["severity"],
        confidence=gt["confidence"],
        mitre_techniques=map_indicators_to_techniques(gt["mitre_indicator_tags"]),
        narrative=gt["narrative"],
        recommended_actions=gt["recommended_actions"],
    )
    report = {
        "scenario_id": scenario.id,
        "alert": scenario.alert,
        "backend_name": "Simulated Reasoning (offline demo - no API key required)",
        "started_at": "2026-06-12T03:10:00+00:00",
        "finished_at": "2026-06-12T03:10:05+00:00",
        "evidence_log": [],
        "verdict": verdict.to_dict(),
        "discovered_indicator_tags": gt["mitre_indicator_tags"],
    }

    markdown = report_to_markdown(report)

    assert markdown.startswith("# Investigation Report:")
    assert "TRUE POSITIVE" in markdown
    assert "CRITICAL" in markdown
    assert "## MITRE ATT&CK Techniques" in markdown
    assert "## Recommended Actions" in markdown
    for action in gt["recommended_actions"]:
        assert action in markdown
