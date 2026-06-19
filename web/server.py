"""FastAPI backend for the Sentinel SOC dashboard.

Serves the static dashboard (``web/static/``) and a Server-Sent-Events
endpoint that streams a live investigation trace as :class:`TriageAgent`
works through a scenario.

Run with::

    python web/server.py

or::

    uvicorn web.server:app --reload
"""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles

from agent.config import get_config
from agent.llm_client import get_llm_client
from agent.scenarios import get_scenario, list_scenarios
from agent.triage_agent import TriageAgent

STATIC_DIR = Path(__file__).resolve().parent / "static"

app = FastAPI(title="Sentinel SOC Dashboard")
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


@app.get("/")
async def index() -> FileResponse:
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/api/status")
async def status() -> dict:
    """Report the active reasoning backend and mode, for the UI header."""

    config = get_config()
    scenarios = list_scenarios()
    try:
        llm = get_llm_client(config, scenarios[0] if config.is_mock and scenarios else None)
        backend_name = llm.name
    except Exception as exc:  # noqa: BLE001
        backend_name = f"not configured ({exc})"

    return {
        "mode": "mock" if config.is_mock else "live",
        "backend_name": backend_name,
        "max_steps": config.agent_max_steps,
    }


@app.get("/api/scenarios")
async def scenarios() -> list[dict]:
    return [
        {
            "id": s.id,
            "title": s.title,
            "category": s.category,
            "short_description": s.short_description,
            "alert": s.alert,
            "step_count": s.step_count,
        }
        for s in list_scenarios()
    ]


@app.get("/api/investigate/{scenario_id}")
async def investigate(scenario_id: str) -> StreamingResponse:
    try:
        scenario = get_scenario(scenario_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc

    config = get_config()

    async def event_stream():
        agent = TriageAgent(config, scenario)
        try:
            async for event in agent.investigate():
                payload = json.dumps(event.to_dict(), default=str)
                yield f"data: {payload}\n\n"
                if config.is_mock and config.demo_step_delay_seconds > 0:
                    await asyncio.sleep(config.demo_step_delay_seconds)
        except Exception as exc:  # noqa: BLE001
            error_payload = json.dumps({"type": "error", "content": f"{type(exc).__name__}: {exc}"})
            yield f"data: {error_payload}\n\n"

    return StreamingResponse(
        event_stream(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


def main() -> None:
    import uvicorn

    config = get_config()
    uvicorn.run(app, host=config.web_host, port=config.web_port)


if __name__ == "__main__":
    main()
