"""Tests for the FastAPI web backend: status, scenario list, and the SSE
investigation stream.
"""

from __future__ import annotations

import json

from fastapi.testclient import TestClient

from web.server import app

client = TestClient(app)


def test_root_serves_dashboard():
    response = client.get("/")
    assert response.status_code == 200
    assert "Sentinel" in response.text


def test_api_status_reports_mode_and_backend(monkeypatch):
    monkeypatch.setenv("SPLUNK_MODE", "mock")

    response = client.get("/api/status")

    assert response.status_code == 200
    data = response.json()
    assert data["mode"] == "mock"
    assert data["backend_name"]
    assert data["max_steps"] >= 1


def test_api_scenarios_lists_bundled_scenarios():
    response = client.get("/api/scenarios")

    assert response.status_code == 200
    scenarios = response.json()
    ids = {s["id"] for s in scenarios}
    assert ids == {
        "powershell_encoded_cmd",
        "brute_force_credential_access",
        "insider_data_staging_exfil",
    }
    for scenario in scenarios:
        assert scenario["alert"]["rule_name"]
        assert scenario["step_count"] > 0


def test_investigate_unknown_scenario_returns_404():
    response = client.get("/api/investigate/does-not-exist")
    assert response.status_code == 404


def test_investigate_stream_runs_to_verdict(monkeypatch):
    monkeypatch.setenv("SPLUNK_MODE", "mock")
    monkeypatch.setenv("DEMO_STEP_DELAY_SECONDS", "0")

    response = client.get("/api/investigate/brute_force_credential_access")

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/event-stream")

    events = [
        json.loads(line[len("data: "):])
        for line in response.text.splitlines()
        if line.startswith("data: ")
    ]

    assert events[0]["type"] == "start"
    assert events[-1]["type"] == "verdict"
    assert events[-1]["verdict"]["verdict"] == "true_positive"
    assert not any(e["type"] == "error" for e in events)
