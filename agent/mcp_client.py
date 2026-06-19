"""Unified client for the tools the triage agent can call.

Two backends share one interface (:class:`SplunkMCPClient`):

* **mock** (default) - serves bundled BOTS-inspired scenario data via
  :class:`agent.mock_backend.MockSplunkBackend`. Zero infrastructure.
* **live** - connects to a real `Splunk MCP Server
  <https://www.splunk.com>`_ (GA Feb 2026) over stdio or SSE using the
  official ``mcp`` Python SDK, and forwards tool calls to it.

The tool catalog mirrors the Splunk MCP Server's naming convention:
``splunk_*`` tools talk to core Splunk search, and ``saia_*`` tools call the
Splunk AI Assistant for SPL. ``get_asset_context`` / ``get_identity_context``
are enrichment tools - in a live deployment these would be backed by Splunk
lookups (e.g. ``| inputlookup asset_inventory.csv``) exposed as a custom MCP
tool; here they are served by the same backend as everything else.
"""

from __future__ import annotations

import json
import logging
from contextlib import AsyncExitStack
from typing import Any

from .config import Config
from .mock_backend import MockSplunkBackend, ToolResult
from .scenarios import Scenario

logger = logging.getLogger(__name__)

__all__ = ["SplunkMCPClient", "ToolResult", "TOOL_CATALOG"]


TOOL_CATALOG: list[dict[str, Any]] = [
    {
        "name": "splunk_search",
        "description": (
            "Run a Splunk SPL search and return matching events or stats. "
            "Use this to pull raw logs: process telemetry, network traffic, "
            "DNS, authentication events, DLP alerts, etc."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "query": {
                    "type": "string",
                    "description": "The SPL search string, e.g. 'search index=endpoint host=X ...'",
                },
                "earliest_time": {
                    "type": "string",
                    "description": "Earliest time bound, e.g. '-24h' or an ISO-8601 timestamp.",
                    "default": "-24h",
                },
                "latest_time": {
                    "type": "string",
                    "description": "Latest time bound, e.g. 'now' or an ISO-8601 timestamp.",
                    "default": "now",
                },
            },
            "required": ["query"],
        },
    },
    {
        "name": "saia_generate_spl",
        "description": (
            "Ask the Splunk AI Assistant for SPL to translate a natural-language "
            "question into SPL (and run it). Useful for ad-hoc analysis like "
            "'decode this base64 PowerShell command line'."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "question": {"type": "string", "description": "A natural-language question about the data."}
            },
            "required": ["question"],
        },
    },
    {
        "name": "saia_explain_spl",
        "description": "Ask the Splunk AI Assistant for SPL to explain in plain English what a given SPL query does.",
        "input_schema": {
            "type": "object",
            "properties": {"spl": {"type": "string", "description": "The SPL query to explain."}},
            "required": ["spl"],
        },
    },
    {
        "name": "get_asset_context",
        "description": (
            "Look up CMDB / asset-inventory context for a hostname or IP address: "
            "category, department, criticality, and ownership."
        ),
        "input_schema": {
            "type": "object",
            "properties": {"asset": {"type": "string", "description": "Hostname or IP address."}},
            "required": ["asset"],
        },
    },
    {
        "name": "get_identity_context",
        "description": (
            "Look up identity/HR context for a username: role, department, "
            "account type, recent activity, badge/VPN status."
        ),
        "input_schema": {
            "type": "object",
            "properties": {"user": {"type": "string", "description": "Username, e.g. 'jchen' or 'DOMAIN\\\\jchen'."}},
            "required": ["user"],
        },
    },
]


class SplunkMCPClient:
    """Async context manager exposing ``list_tools`` / ``call_tool``.

    Construct one per investigation. In mock mode a ``scenario`` is
    required; in live mode it is ignored.
    """

    def __init__(self, config: Config, scenario: Scenario | None = None):
        self.config = config
        self._mock: MockSplunkBackend | None = None
        self._stack: AsyncExitStack | None = None
        self._session: Any = None

        if config.is_mock:
            if scenario is None:
                raise ValueError("A scenario is required when SPLUNK_MODE=mock")
            self._mock = MockSplunkBackend(scenario)

    async def __aenter__(self) -> "SplunkMCPClient":
        if not self.config.is_mock:
            await self._connect_live()
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        if self._stack is not None:
            await self._stack.aclose()
            self._stack = None
            self._session = None

    # ------------------------------------------------------------------
    # Live MCP connection
    # ------------------------------------------------------------------
    async def _connect_live(self) -> None:
        try:
            from mcp import ClientSession, StdioServerParameters
            from mcp.client.stdio import stdio_client
        except ImportError as exc:  # pragma: no cover - optional dependency
            raise RuntimeError(
                "SPLUNK_MODE=live requires the 'mcp' package. Install it with "
                "'pip install mcp', or set SPLUNK_MODE=mock to use the bundled "
                "offline demo data."
            ) from exc

        self._stack = AsyncExitStack()
        transport = self.config.mcp.transport

        if transport in ("sse", "http"):
            from mcp.client.sse import sse_client

            if not self.config.mcp.server_url:
                raise RuntimeError("MCP_SERVER_URL must be set for MCP_TRANSPORT=sse/http")
            read, write = await self._stack.enter_async_context(
                sse_client(self.config.mcp.server_url)
            )
        else:
            if not self.config.mcp.server_command:
                raise RuntimeError("MCP_SERVER_COMMAND must be set for MCP_TRANSPORT=stdio")

            command, *args = self.config.mcp.server_command.split()
            server_params = StdioServerParameters(
                command=command,
                args=args,
                env={
                    "SPLUNK_HOST": self.config.mcp.splunk_host,
                    "SPLUNK_PORT": self.config.mcp.splunk_port,
                    "SPLUNK_USERNAME": self.config.mcp.splunk_username,
                    "SPLUNK_PASSWORD": self.config.mcp.splunk_password,
                    "SPLUNK_TOKEN": self.config.mcp.splunk_token,
                    "SPLUNK_VERIFY_SSL": "true" if self.config.mcp.verify_ssl else "false",
                },
            )
            read, write = await self._stack.enter_async_context(stdio_client(server_params))

        self._session = await self._stack.enter_async_context(ClientSession(read, write))
        await self._session.initialize()
        logger.info("Connected to Splunk MCP Server via %s", transport)

    # ------------------------------------------------------------------
    # Tool catalog / invocation
    # ------------------------------------------------------------------
    async def list_tools(self) -> list[dict[str, Any]]:
        """Return tool schemas for use as LLM function-calling definitions."""

        if self._session is not None:
            result = await self._session.list_tools()
            return [
                {
                    "name": t.name,
                    "description": t.description or "",
                    "input_schema": t.inputSchema,
                }
                for t in result.tools
            ]
        return TOOL_CATALOG

    async def call_tool(self, name: str, arguments: dict[str, Any]) -> ToolResult:
        if self._mock is not None:
            return self._mock.call_tool(name, arguments)
        return await self._call_live(name, arguments)

    async def _call_live(self, name: str, arguments: dict[str, Any]) -> ToolResult:
        if self._session is None:
            raise RuntimeError("MCP session is not connected (live mode)")

        result = await self._session.call_tool(name, arguments)
        data: Any = None
        for block in result.content:
            text = getattr(block, "text", None)
            if text is None:
                continue
            try:
                data = json.loads(text)
            except json.JSONDecodeError:
                data = text
            break

        return ToolResult(tool=name, arguments=arguments, title=name, data=data, indicator_tags=[])

    # ------------------------------------------------------------------
    # Convenience for mock-mode introspection (used by the CLI/report)
    # ------------------------------------------------------------------
    def discovered_indicator_tags(self) -> list[str]:
        if self._mock is not None:
            return self._mock.all_indicator_tags()
        return []
