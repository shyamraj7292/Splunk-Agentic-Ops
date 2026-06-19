# Sentinel — Architecture

## Overview

Sentinel is a single-process Python application organized around one central
abstraction: `TriageAgent`, an async generator that runs a ReAct (Reason + Act)
loop and yields `TraceEvent` objects as it investigates an alert. The CLI and web
dashboard are thin consumers of that generator — they differ only in how they
render each event.

![Architecture diagram](architecture-diagram.svg)

---

## Component reference

### `agent/config.py` — Configuration

Three frozen dataclasses: `Config`, `MCPConfig`, `LLMConfig`. Every field reads
from an environment variable with a safe default so the agent runs fully in mock
mode with zero setup. `Config.is_mock` returns `True` unless `SPLUNK_MODE=live`.

`get_config()` returns a fresh `Config` from the current environment; both the
CLI and web server call this at startup.

---

### `agent/scenarios.py` — Scenario loader

`Scenario` and `ScenarioStep` are frozen dataclasses loaded from JSON files under
`data/scenarios/`. Each file contains:

- `alert` — the Splunk notable event that triggers the investigation
- `steps` — ordered list of canned evidence steps, each with a tool name,
  keyword `match_any` list, pre-baked result, and `indicator_tags`
- `ground_truth` — expert-authored verdict used by `SimulatedReasoningClient`
  and as the test oracle

`list_scenarios()` returns all bundled scenarios; `get_scenario(id)` raises a
descriptive `KeyError` if the ID is unknown (listing all available IDs in the
message).

---

### `agent/mitre_mapping.py` — ATT&CK knowledge base

Two structures:

- `TECHNIQUES` — dict of technique ID → `Technique` dataclass (id, name, tactic,
  mitre.org URL auto-derived from the ID)
- `INDICATOR_TECHNIQUE_MAP` — dict of indicator tag (e.g. `c2_beaconing`) →
  list of technique IDs

`map_indicators_to_techniques(tags)` takes the collected `indicator_tags` from
an investigation, deduplicates, sorts by technique ID, and returns a list of
`Technique.to_dict()` dicts ready for the final report.

Currently covers 14 ATT&CK techniques across Initial Access, Execution, Defense
Evasion, Credential Access, Persistence, Discovery, Collection, Command and Control,
and Exfiltration — sufficient for the three bundled scenarios and easily extensible.

---

### `agent/mock_backend.py` — Offline Splunk simulation

`MockSplunkBackend` serves canned scenario data in response to MCP-style tool calls,
enabling the full agent to run with zero infrastructure.

**Matching algorithm** (`_best_match`):

1. Score every step for the current tool by counting how many of its `match_any`
   keywords appear in the query text.
2. Among **unused** steps, pick the highest scorer. If all unused steps score zero
   (e.g. a real LLM went off-script), fall back to the next unused step in narrative
   order — so the investigation always keeps progressing.
3. Once every step for that tool has been served, fall back to the best overall
   match (re-serving it without emitting `indicator_tags` again, since they have
   already been discovered).

The tie-breaking rule in step 2 (prefer lower step number when scores are tied) is
tested by a dedicated regression test (`test_mock_backend_resolves_keyword_collision_between_used_and_unused_steps`).

---

### `agent/mcp_client.py` — Unified MCP client

`SplunkMCPClient` is an async context manager with a single interface regardless
of mode:

```python
async with SplunkMCPClient(config, scenario) as client:
    tools = await client.list_tools()          # returns TOOL_CATALOG (mock) or live server tools
    result = await client.call_tool(name, args) # returns ToolResult
```

**Mock mode** delegates to `MockSplunkBackend`. **Live mode** connects to the
Splunk MCP Server (GA February 2026) using the `mcp` Python SDK, either via
`stdio_client` (subprocess) or `sse_client` (network), as configured by
`MCP_TRANSPORT`.

The tool catalog (`TOOL_CATALOG`) mirrors the Splunk MCP Server's naming convention:

| Tool | Purpose |
|---|---|
| `splunk_search` | Run an SPL query and return matching events or stats |
| `saia_generate_spl` | Natural-language → SPL (Splunk AI Assistant) |
| `saia_explain_spl` | Explain an SPL query in plain English |
| `get_asset_context` | CMDB/asset-inventory lookup by hostname or IP |
| `get_identity_context` | HR/identity lookup by username |

---

### `agent/llm_client.py` — Reasoning backends

Defines the `LLMClient` protocol (two methods: `decide_next_action` and
`finalize_verdict`) and three implementations selected by `get_llm_client()`:

#### `FoundationSecClient` — Splunk hosted model
Connects to Splunk's Foundation-sec model over an OpenAI-compatible endpoint
(`FOUNDATION_SEC_BASE_URL`). Sends structured system prompts that describe the tool
catalog and ask for JSON-only responses (`AgentAction` shape for actions,
`Verdict` shape for finalization). Extracts JSON with a best-effort regex fallback
if the model includes surrounding prose.

#### `AnthropicClient` — Fallback reasoning
Uses the Anthropic Python SDK with identical prompt templates. Same JSON extraction
logic. Activated when `ANTHROPIC_API_KEY` is set and Foundation-sec is not
configured.

#### `SimulatedReasoningClient` — Offline demo
Deterministic, scenario-aware. Walks the scenario's steps in narrative order,
generates analyst-style "thought" strings from templates, then returns the
scenario's `ground_truth` as the final `Verdict`. Enables the full demo — including
the web UI — with zero API keys and zero network access.

**Priority**: Foundation-sec → Anthropic Claude → Simulated Reasoning (first match wins).

---

### `agent/triage_agent.py` — ReAct investigation loop

`TriageAgent.investigate()` is an `AsyncIterator[TraceEvent]`. Call sequence:

```
yield TraceEvent(type="start")
async with SplunkMCPClient(...) as client:
    tools = await client.list_tools()
    while step < max_steps:
        action = await llm.decide_next_action(alert, history, tools)
        yield TraceEvent(type="thought", content=action.thought)
        if action.action == "finalize": break
        yield TraceEvent(type="action", tool=..., arguments=...)
        result = await client.call_tool(action.tool_name, action.tool_arguments)
        discovered_tags += result.indicator_tags          # de-duplicated
        history.append({tool, args, title, data, tags})
        yield TraceEvent(type="observation", ...)
    verdict = await llm.finalize_verdict(alert, history)
# MITRE merge: indicator-tag baseline fills gaps the model missed
verdict.mitre_techniques = _merge_techniques(verdict.mitre_techniques, baseline)
report = InvestigationReport(...)
yield TraceEvent(type="verdict", content=report.to_dict())
```

`_merge_techniques` combines the LLM's cited techniques with the
`map_indicators_to_techniques(discovered_tags)` baseline — the LLM's entries take
precedence for the same technique ID, but the baseline fills in anything the model
forgot to cite.

---

### `agent/report.py` — Data models and Markdown rendering

**`TraceEvent`** — a single step in the streaming trace:

| `type` | Key fields |
|---|---|
| `start` | `content` (description string) |
| `thought` | `step`, `content` (analyst reasoning text) |
| `action` | `step`, `tool`, `arguments` |
| `observation` | `step`, `tool`, `title`, `data`, `indicator_tags` |
| `verdict` | `verdict` (Verdict dict), `content` (full InvestigationReport dict) |
| `error` | `content` (error description) |

`to_dict()` omits `None` and empty-list fields so the SSE payload stays compact.

**`InvestigationReport`** — the final structured output: scenario ID, alert,
backend name, time range, evidence log, `Verdict`, discovered indicator tags.
`to_dict()` serializes it for JSON/SSE; `to_markdown()` delegates to
`report_to_markdown()`.

**`report_to_markdown(report_dict)`** — renders a Markdown document with verdict
badge, alert fields, narrative, MITRE ATT&CK table (with mitre.org links), a
`- [ ]` recommended-actions checklist, and an evidence log. Used by the CLI to
write `{save_dir}/{scenario_id}.md`.

---

### `scripts/run_demo.py` — CLI demo runner

Accepts `--list`, `--scenario <id>`, `--all`, `--save-dir <dir>`, `--no-rich`.
Calls `TriageAgent.investigate()`, renders each `TraceEvent` with `rich` (falls
back to plain text if `--no-rich` or if `rich` is not installed), and saves a
Markdown report to `{save_dir}/{scenario_id}.md`.

### `scripts/setup_check.py` — Day-0 verification

Checks Python version, all required and optional packages, scenario loading,
mock-mode agent startup, and active LLM backend. Prints a clear PASS/SKIP/FAIL
summary so new contributors can confirm their environment in seconds.

---

### `web/server.py` — FastAPI backend

Four routes:

| Route | Description |
|---|---|
| `GET /` | Serves `web/static/index.html` |
| `GET /api/status` | Returns `{mode, backend_name, max_steps}` |
| `GET /api/scenarios` | Returns list of scenario summaries |
| `GET /api/investigate/{id}` | SSE stream — runs `TriageAgent.investigate()` and yields each `TraceEvent` as `data: <json>\n\n` |

The SSE route uses `StreamingResponse(media_type="text/event-stream")` with
`Cache-Control: no-cache` and `X-Accel-Buffering: no` headers. In mock mode it
inserts a `DEMO_STEP_DELAY_SECONDS` sleep between events so the web UI visibly
"thinks". Errors are caught and emitted as `{"type": "error", ...}` events so the
client always gets a well-formed stream.

### `web/static/` — SOC dashboard

- **`index.html`** — layout: topbar, scenario sidebar (`#scenario-list`), main
  column with alert panel (`#alert-panel`), live trace panel (`#trace-panel`), and
  final report panel (`#report-panel`).
- **`style.css`** — dark SOC theme via CSS variables (`--bg`, `--bg-panel`,
  `--accent`, `--critical`, `--high`, `--medium`, `--low`, verdict colors). Trace
  events are color-coded by type via left-border accent colors.
- **`app.js`** — vanilla JS with `EventSource`. `loadScenarios()` populates the
  sidebar; `runInvestigation()` opens an `EventSource` to `/api/investigate/{id}`,
  dispatches each event to `appendTraceEvent()`, and on the final `"verdict"` event
  calls `renderReport()` to populate the structured report panel.

---

## Data flow summary

```
Alert JSON (from Scenario)
  │
  ▼
TriageAgent.investigate()           ◄─── Config (SPLUNK_MODE, AGENT_MAX_STEPS, ...)
  │
  ├── [each ReAct step]
  │     ├── LLMClient.decide_next_action(alert, history, tools)
  │     │         └── Foundation-sec / Claude / Simulated → AgentAction (thought + tool call)
  │     ├── SplunkMCPClient.call_tool(name, args)
  │     │         └── MockSplunkBackend (mock) / Splunk MCP Server (live) → ToolResult
  │     └── yield TraceEvent(type="thought"|"action"|"observation")
  │
  ├── LLMClient.finalize_verdict(alert, history) → Verdict
  ├── map_indicators_to_techniques(discovered_tags) → MITRE baseline
  ├── _merge_techniques(llm_techniques, baseline) → final technique list
  └── yield TraceEvent(type="verdict", content=InvestigationReport.to_dict())
              │
              ├── CLI: report_to_markdown() → {save_dir}/{id}.md
              └── Web: SSE "data: {...}\n\n" → app.js renderReport()
```

---

## Mock vs. live mode

| Aspect | `SPLUNK_MODE=mock` (default) | `SPLUNK_MODE=live` |
|---|---|---|
| Splunk data source | `MockSplunkBackend` (in-process) | Real Splunk via MCP Server |
| MCP SDK | Not used | `mcp` SDK, stdio or SSE transport |
| Reasoning | `SimulatedReasoningClient` (unless API key set) | Foundation-sec or Claude |
| Infrastructure needed | None | Splunk instance + MCP Server process |
| Test isolation | Full — deterministic, no network | Requires live credentials |
| Demo delay | `DEMO_STEP_DELAY_SECONDS=0.5` adds pacing | Real tool latency provides pacing |

The offline mock is the intended demo path. The live path is production-ready but
requires a running Splunk MCP Server (see `.env.example`).

---

## Extending Sentinel

**Add a new scenario** — create `data/scenarios/<id>.json` following the schema of
the existing files. No code changes needed; `list_scenarios()` discovers all JSON
files in that directory automatically.

**Add a new MCP tool** — add an entry to `TOOL_CATALOG` in `agent/mcp_client.py`
and a matching `QUERY_ARG_BY_TOOL` entry in `agent/mock_backend.py`.

**Add a new LLM backend** — implement the `LLMClient` protocol
(`decide_next_action` / `finalize_verdict`) and add a branch to `get_llm_client()`.

**Add new ATT&CK techniques** — add entries to `TECHNIQUES` and
`INDICATOR_TECHNIQUE_MAP` in `agent/mitre_mapping.py`.
