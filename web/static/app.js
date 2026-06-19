"use strict";

const state = {
  scenarios: [],
  selected: null,
  eventSource: null,
};

const VERDICT_LABELS = {
  true_positive: "TRUE POSITIVE",
  false_positive: "FALSE POSITIVE",
  escalate: "ESCALATE",
};

const ALERT_FIELD_LABELS = [
  ["time", "Time"],
  ["host", "Host"],
  ["user", "User"],
  ["src_ip", "Source IP"],
  ["dest_domain", "Destination Domain"],
  ["source", "Source"],
];

const TRACE_META = {
  start: { icon: "\u{1F680}", label: "Investigation Started" },
  thought: { icon: "\u{1F9E0}", label: "Analyst Reasoning" },
  action: { icon: "\u{1F527}", label: "Tool Call" },
  observation: { icon: "\u{1F4C4}", label: "Evidence" },
  error: { icon: "⚠️", label: "Error" },
  done: { icon: "✅", label: "Investigation Complete" },
};

document.addEventListener("DOMContentLoaded", init);

async function init() {
  loadStatus();
  await loadScenarios();
  document.getElementById("run-btn").addEventListener("click", runInvestigation);
}

async function loadStatus() {
  const dot = document.getElementById("status-dot");
  const text = document.getElementById("status-text");
  try {
    const res = await fetch("/api/status");
    const data = await res.json();
    dot.className = "status-dot " + (data.mode === "mock" ? "mock" : "live");
    text.textContent = `${data.mode.toUpperCase()} · ${data.backend_name} · max ${data.max_steps} steps`;
  } catch (err) {
    text.textContent = "status unavailable";
  }
}

async function loadScenarios() {
  const res = await fetch("/api/scenarios");
  state.scenarios = await res.json();
  renderScenarioList();
}

function renderScenarioList() {
  const container = document.getElementById("scenario-list");
  container.innerHTML = "";

  for (const scenario of state.scenarios) {
    const severity = (scenario.alert.severity || "medium").toLowerCase();

    const card = document.createElement("button");
    card.type = "button";
    card.className = "scenario-card";
    card.dataset.id = scenario.id;
    card.innerHTML = `
      <div class="scenario-card-header">
        <span class="severity-pill ${escapeHtml(severity)}">${escapeHtml(severity)}</span>
        <span class="category-pill">${escapeHtml(scenario.category)}</span>
      </div>
      <h3>${escapeHtml(scenario.title)}</h3>
      <p>${escapeHtml(scenario.short_description)}</p>
      <div class="scenario-card-footer">
        <span>${escapeHtml(scenario.alert.host || "")}</span>
        <span>${scenario.step_count} evidence steps</span>
      </div>
    `;
    card.addEventListener("click", () => selectScenario(scenario.id));
    container.appendChild(card);
  }
}

function selectScenario(id) {
  if (state.eventSource) {
    state.eventSource.close();
    state.eventSource = null;
  }

  state.selected = state.scenarios.find((s) => s.id === id);

  document
    .querySelectorAll(".scenario-card")
    .forEach((card) => card.classList.toggle("active", card.dataset.id === id));

  document.getElementById("empty-state").classList.add("hidden");
  document.getElementById("trace-panel").classList.add("hidden");
  document.getElementById("report-panel").classList.add("hidden");
  document.getElementById("trace-events").innerHTML = "";
  setTraceStatus("");

  renderAlertPanel();
}

function renderAlertPanel() {
  const scenario = state.selected;
  const alert = scenario.alert;
  const panel = document.getElementById("alert-panel");
  panel.classList.remove("hidden");

  document.getElementById("alert-title").textContent = alert.rule_name || scenario.title;
  document.getElementById("alert-description").textContent = alert.description || scenario.short_description;
  document.getElementById("alert-category").textContent = scenario.category;

  const severity = (alert.severity || "medium").toLowerCase();
  const sevBadge = document.getElementById("alert-severity");
  sevBadge.textContent = severity.toUpperCase();
  sevBadge.className = "severity-badge " + severity;

  const grid = document.getElementById("alert-grid");
  grid.innerHTML = "";
  for (const [key, label] of ALERT_FIELD_LABELS) {
    if (alert[key] === undefined || alert[key] === null || alert[key] === "") continue;
    const field = document.createElement("div");
    field.className = "alert-field";
    field.innerHTML = `<span class="alert-field-label">${escapeHtml(label)}</span><span class="alert-field-value">${escapeHtml(String(alert[key]))}</span>`;
    grid.appendChild(field);
  }

  const rawEl = document.getElementById("alert-raw");
  if (alert.raw) {
    rawEl.textContent = alert.raw;
    rawEl.classList.remove("hidden");
  } else {
    rawEl.classList.add("hidden");
  }

  const runBtn = document.getElementById("run-btn");
  runBtn.disabled = false;
  runBtn.textContent = "Run Investigation";
}

function runInvestigation() {
  if (!state.selected) return;

  if (state.eventSource) {
    state.eventSource.close();
    state.eventSource = null;
  }

  const tracePanel = document.getElementById("trace-panel");
  const reportPanel = document.getElementById("report-panel");
  const traceEvents = document.getElementById("trace-events");
  const runBtn = document.getElementById("run-btn");

  tracePanel.classList.remove("hidden");
  reportPanel.classList.add("hidden");
  traceEvents.innerHTML = "";
  setTraceStatus("running");

  runBtn.disabled = true;
  runBtn.textContent = "Investigating…";

  tracePanel.scrollIntoView({ behavior: "smooth", block: "start" });

  const es = new EventSource(`/api/investigate/${encodeURIComponent(state.selected.id)}`);
  state.eventSource = es;

  es.onmessage = (evt) => {
    let payload;
    try {
      payload = JSON.parse(evt.data);
    } catch (err) {
      return;
    }
    handleTraceEvent(payload);
  };

  es.onerror = () => {
    if (es.readyState === EventSource.CLOSED) return;
    setTraceStatus("error");
    appendTraceEvent({ type: "error", content: "Connection to the investigation stream was lost." });
    finishInvestigation();
  };
}

function handleTraceEvent(event) {
  if (event.type === "verdict") {
    appendTraceEvent({ type: "done", content: "Verdict rendered — see the report below." });
    renderReport(event.content);
    setTraceStatus("done");
    finishInvestigation();
    return;
  }

  if (event.type === "error") {
    setTraceStatus("error");
    appendTraceEvent(event);
    finishInvestigation();
    return;
  }

  appendTraceEvent(event);
}

function finishInvestigation() {
  if (state.eventSource) {
    state.eventSource.close();
    state.eventSource = null;
  }
  const runBtn = document.getElementById("run-btn");
  runBtn.disabled = false;
  runBtn.textContent = "Run Investigation Again";
}

function setTraceStatus(status) {
  const el = document.getElementById("trace-status");
  el.className = "trace-status" + (status ? " " + status : "");
  el.textContent = {
    running: "RUNNING",
    done: "COMPLETE",
    error: "ERROR",
    "": "",
  }[status] ?? status.toUpperCase();
}

function appendTraceEvent(event) {
  const container = document.getElementById("trace-events");
  const meta = TRACE_META[event.type] || { icon: "•", label: event.type };

  const el = document.createElement("div");
  el.className = `trace-event trace-event--${event.type}`;

  const head = document.createElement("div");
  head.className = "trace-event-head";
  head.innerHTML = `<span class="trace-event-icon">${meta.icon}</span><span>${escapeHtml(meta.label)}</span>`;
  if (event.step) {
    const step = document.createElement("span");
    step.className = "trace-event-step";
    step.textContent = `step ${event.step}`;
    head.appendChild(step);
  }
  el.appendChild(head);

  const body = document.createElement("div");
  body.className = "trace-event-body";

  if (event.type === "thought" || event.type === "start" || event.type === "done" || event.type === "error") {
    body.textContent = event.content || "";
  } else if (event.type === "action") {
    const title = document.createElement("div");
    title.className = "trace-event-title";
    title.innerHTML = `Calling <code>${escapeHtml(event.tool || "")}</code>`;
    body.appendChild(title);
    if (event.arguments && Object.keys(event.arguments).length) {
      body.appendChild(jsonBlock(event.arguments));
    }
  } else if (event.type === "observation") {
    if (event.title) {
      const title = document.createElement("div");
      title.className = "trace-event-title";
      title.textContent = event.title;
      body.appendChild(title);
    }
    if (event.tool) {
      const toolLine = document.createElement("div");
      toolLine.className = "muted";
      toolLine.innerHTML = `<code>${escapeHtml(event.tool)}</code>`;
      body.appendChild(toolLine);
    }
    if (event.data !== undefined) {
      body.appendChild(jsonBlock(event.data));
    }
    if (event.indicator_tags && event.indicator_tags.length) {
      const tagRow = document.createElement("div");
      tagRow.className = "tag-row";
      for (const tag of event.indicator_tags) {
        const pill = document.createElement("span");
        pill.className = "tag-pill";
        pill.textContent = tag;
        tagRow.appendChild(pill);
      }
      body.appendChild(tagRow);
    }
  } else {
    body.textContent = JSON.stringify(event);
  }

  el.appendChild(body);
  container.appendChild(el);
  container.scrollTop = container.scrollHeight;
}

function jsonBlock(data) {
  const pre = document.createElement("pre");
  pre.className = "data-block";
  pre.textContent = JSON.stringify(data, null, 2);
  return pre;
}

function renderReport(report) {
  const verdict = report.verdict;
  const panel = document.getElementById("report-panel");
  panel.classList.remove("hidden");

  const verdictEl = document.getElementById("report-verdict");
  verdictEl.textContent = VERDICT_LABELS[verdict.verdict] || verdict.verdict.toUpperCase();
  verdictEl.className = "verdict-badge " + verdict.verdict;

  const severityEl = document.getElementById("report-severity");
  severityEl.textContent = verdict.severity.toUpperCase();
  severityEl.className = "severity-badge " + verdict.severity.toLowerCase();

  const pct = Math.round(verdict.confidence * 100);
  document.getElementById("report-confidence-fill").style.width = pct + "%";
  document.getElementById("report-confidence-text").textContent = pct + "%";

  document.getElementById("report-narrative").textContent = verdict.narrative;

  const meta = document.getElementById("report-meta");
  const indicatorTags = report.discovered_indicator_tags || [];
  meta.innerHTML = `
    <div>
      <span class="meta-label">Reasoning Engine</span>
      <span>${escapeHtml(report.backend_name)}</span>
    </div>
    <div>
      <span class="meta-label">Investigation Window</span>
      <span>${escapeHtml(formatRange(report.started_at, report.finished_at))}</span>
    </div>
    <div>
      <span class="meta-label">Indicators Discovered</span>
      <span>${indicatorTags.length ? escapeHtml(indicatorTags.join(", ")) : "none"}</span>
    </div>
  `;

  const mitre = document.getElementById("report-mitre");
  mitre.innerHTML = "";
  const techniques = verdict.mitre_techniques || [];
  if (techniques.length === 0) {
    mitre.innerHTML = '<p class="muted">No specific techniques mapped.</p>';
  }
  for (const t of techniques) {
    const a = document.createElement("a");
    a.className = "mitre-chip";
    a.href = t.url || "#";
    a.target = "_blank";
    a.rel = "noopener";
    a.innerHTML = `<strong>${escapeHtml(t.id)}</strong><span>${escapeHtml(t.name)}</span><em>${escapeHtml(t.tactic)}</em>`;
    mitre.appendChild(a);
  }

  const actions = document.getElementById("report-actions");
  actions.innerHTML = "";
  for (const action of verdict.recommended_actions || []) {
    const li = document.createElement("li");
    const label = document.createElement("label");
    const checkbox = document.createElement("input");
    checkbox.type = "checkbox";
    const span = document.createElement("span");
    span.textContent = action;
    label.appendChild(checkbox);
    label.appendChild(span);
    li.appendChild(label);
    actions.appendChild(li);
  }
}

function formatRange(start, end) {
  try {
    const s = new Date(start);
    const e = new Date(end);
    const durationSeconds = Math.max(0, (e - s) / 1000).toFixed(1);
    return `${s.toLocaleTimeString()} → ${e.toLocaleTimeString()} (${durationSeconds}s)`;
  } catch (err) {
    return `${start} → ${end}`;
  }
}

function escapeHtml(value) {
  const div = document.createElement("div");
  div.textContent = value ?? "";
  return div.innerHTML;
}
