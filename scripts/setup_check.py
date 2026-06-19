#!/usr/bin/env python
"""Day-0 environment verification for the Sentinel triage agent.

Run this FIRST, before anything else::

    python scripts/setup_check.py

It checks (without requiring any configuration):

* Python version and optional dependencies
* That the bundled BOTS-inspired scenario data loads correctly
* Your ``SPLUNK_MODE`` / MCP / LLM configuration and what it implies

Add ``--connect`` to additionally test live network connections to the
Splunk MCP Server and/or the configured LLM backend. These are skipped by
default because they may not be configured yet (mock mode needs neither).
"""

from __future__ import annotations

import argparse
import asyncio
import importlib
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

if sys.stdout.encoding and sys.stdout.encoding.lower() != "utf-8":
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stderr.reconfigure(encoding="utf-8")

from agent.config import get_config  # noqa: E402

SYMBOLS = {"ok": "[ OK ]", "warn": "[WARN]", "fail": "[FAIL]", "skip": "[SKIP]"}


class Check:
    def __init__(self, name: str):
        self.name = name
        self.status = "skip"
        self.detail = ""

    def ok(self, detail: str = "") -> "Check":
        self.status, self.detail = "ok", detail
        return self

    def warn(self, detail: str = "") -> "Check":
        self.status, self.detail = "warn", detail
        return self

    def fail(self, detail: str = "") -> "Check":
        self.status, self.detail = "fail", detail
        return self

    def skip(self, detail: str = "") -> "Check":
        self.status, self.detail = "skip", detail
        return self

    def print(self) -> None:
        print(f"{SYMBOLS[self.status]} {self.name:<32} {self.detail}")


# ---------------------------------------------------------------------------
# Static checks (no network)
# ---------------------------------------------------------------------------


def check_python_version() -> Check:
    c = Check("Python version")
    version = sys.version.split()[0]
    if sys.version_info >= (3, 10):
        return c.ok(version)
    return c.warn(f"{version} - 3.10+ recommended")


def check_dependencies() -> list[Check]:
    checks = []
    for module, label, required in [
        ("dotenv", "python-dotenv", False),
        ("httpx", "httpx", False),
        ("pydantic", "pydantic", False),
        ("fastapi", "fastapi (web UI)", False),
        ("uvicorn", "uvicorn (web UI)", False),
        ("rich", "rich (CLI output)", False),
        ("mcp", "mcp (live Splunk mode)", False),
        ("openai", "openai (Foundation-sec client)", False),
        ("anthropic", "anthropic (fallback LLM)", False),
    ]:
        c = Check(label)
        try:
            importlib.import_module(module)
            c.ok("installed")
        except ImportError:
            (c.fail if required else c.warn)("not installed (pip install -r requirements.txt)")
        checks.append(c)
    return checks


def check_scenarios() -> Check:
    c = Check("Bundled scenario data")
    try:
        from agent.scenarios import list_scenarios

        scenarios = list_scenarios()
        if not scenarios:
            return c.fail("no scenario JSON files found under data/scenarios/")
        ids = ", ".join(s.id for s in scenarios)
        return c.ok(f"{len(scenarios)} scenarios loaded: {ids}")
    except Exception as exc:  # noqa: BLE001
        return c.fail(f"{type(exc).__name__}: {exc}")


def check_mode(config) -> Check:
    c = Check("SPLUNK_MODE")
    if config.is_mock:
        return c.ok("mock - offline demo, no Splunk instance required")
    return c.warn("live - requires a reachable Splunk MCP Server (see checks below)")


def check_mcp_config(config) -> Check:
    c = Check("MCP server configuration")
    if config.is_mock:
        return c.skip("not needed in mock mode")

    if config.mcp.transport == "stdio":
        if config.mcp.server_command:
            return c.ok(f"stdio -> '{config.mcp.server_command}'")
        return c.fail("MCP_TRANSPORT=stdio but MCP_SERVER_COMMAND is not set")

    if config.mcp.transport in ("sse", "http"):
        if config.mcp.server_url:
            return c.ok(f"{config.mcp.transport} -> {config.mcp.server_url}")
        return c.fail(f"MCP_TRANSPORT={config.mcp.transport} but MCP_SERVER_URL is not set")

    return c.fail(f"unknown MCP_TRANSPORT '{config.mcp.transport}' (expected stdio/sse/http)")


def check_splunk_credentials(config) -> Check:
    c = Check("Splunk credentials")
    if config.is_mock:
        return c.skip("not needed in mock mode")
    if config.mcp.splunk_token or config.mcp.splunk_password:
        return c.ok(f"host={config.mcp.splunk_host}:{config.mcp.splunk_port}, user={config.mcp.splunk_username}")
    return c.warn("neither SPLUNK_TOKEN nor SPLUNK_PASSWORD is set")


def check_llm_backend(config) -> Check:
    c = Check("LLM reasoning backend")
    if config.llm.foundation_sec_base_url:
        return c.ok(
            f"Foundation-sec hosted model @ {config.llm.foundation_sec_base_url} "
            f"(model={config.llm.foundation_sec_model}) - eligible for Best Use of Hosted Models"
        )
    if config.llm.anthropic_api_key:
        return c.ok(f"Anthropic Claude (model={config.llm.anthropic_model})")
    if config.is_mock:
        return c.ok("none configured - using offline simulated reasoning (fine for the demo)")
    return c.fail(
        "live mode requires FOUNDATION_SEC_BASE_URL or ANTHROPIC_API_KEY "
        "(simulated reasoning only works with SPLUNK_MODE=mock)"
    )


# ---------------------------------------------------------------------------
# Live connectivity checks (--connect)
# ---------------------------------------------------------------------------


async def check_mcp_connection(config) -> Check:
    c = Check("MCP server connection")
    if config.is_mock:
        return c.skip("not needed in mock mode")

    try:
        from agent.mcp_client import SplunkMCPClient

        async def _try() -> int:
            async with SplunkMCPClient(config) as client:
                tools = await client.list_tools()
                return len(tools)

        n_tools = await asyncio.wait_for(_try(), timeout=20)
        return c.ok(f"connected, {n_tools} tools available")
    except asyncio.TimeoutError:
        return c.fail("timed out after 20s connecting to the MCP server")
    except Exception as exc:  # noqa: BLE001
        return c.fail(f"{type(exc).__name__}: {exc}")


async def check_llm_connection(config) -> Check:
    c = Check("LLM backend connection")
    if not config.llm.foundation_sec_base_url and not config.llm.anthropic_api_key:
        return c.skip("simulated reasoning does not require a connection")

    try:
        from agent.llm_client import get_llm_client

        llm = get_llm_client(config)
        alert = {"rule_name": "setup_check ping", "description": "connectivity test"}
        tools = [{"name": "noop", "description": "no-op tool used only for this connectivity check"}]

        async def _try():
            return await llm.decide_next_action(alert, [], tools)

        action = await asyncio.wait_for(_try(), timeout=30)
        return c.ok(f"{llm.name} responded (action={action.action})")
    except asyncio.TimeoutError:
        return c.fail("timed out after 30s waiting for the LLM backend")
    except Exception as exc:  # noqa: BLE001
        return c.fail(f"{type(exc).__name__}: {exc}")


# ---------------------------------------------------------------------------
# Driver
# ---------------------------------------------------------------------------


async def main_async(args: argparse.Namespace) -> int:
    config = get_config()
    checks: list[Check] = []

    print("Sentinel - environment check\n")

    checks.append(check_python_version())
    checks.extend(check_dependencies())
    checks.append(check_scenarios())
    checks.append(check_mode(config))
    checks.append(check_mcp_config(config))
    checks.append(check_splunk_credentials(config))
    checks.append(check_llm_backend(config))

    if args.connect:
        checks.append(await check_mcp_connection(config))
        checks.append(await check_llm_connection(config))

    for c in checks:
        c.print()

    n_fail = sum(1 for c in checks if c.status == "fail")
    n_warn = sum(1 for c in checks if c.status == "warn")

    print()
    if n_fail:
        print(f"{n_fail} check(s) FAILED - resolve these before running the live demo.")
        return 1
    if n_warn:
        print(f"{n_warn} check(s) have warnings, but the offline mock demo will work fine:")
        print("  python scripts/run_demo.py --scenario powershell_encoded_cmd")
    else:
        print("All checks passed. Try:")
        print("  python scripts/run_demo.py --scenario powershell_encoded_cmd")
    if not args.connect and not config.is_mock:
        print("\nTip: re-run with --connect to test live MCP/LLM connectivity.")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--connect", action="store_true", help="Also test live MCP/LLM network connections")
    args = parser.parse_args()
    return asyncio.run(main_async(args))


if __name__ == "__main__":
    raise SystemExit(main())
