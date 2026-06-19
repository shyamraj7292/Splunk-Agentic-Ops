"""Centralized configuration for the Sentinel triage agent.

All configuration is read from environment variables (optionally loaded from
a local ``.env`` file via python-dotenv). Every setting has a safe default so
the agent runs end-to-end in offline "mock" mode with zero configuration.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field

try:  # pragma: no cover - optional dependency
    from dotenv import load_dotenv

    load_dotenv()
except ImportError:  # pragma: no cover
    pass


def _bool(value: str | None, default: bool = False) -> bool:
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class MCPConfig:
    """Connection settings for the Splunk MCP Server."""

    transport: str = field(default_factory=lambda: os.getenv("MCP_TRANSPORT", "stdio"))
    server_command: str = field(default_factory=lambda: os.getenv("MCP_SERVER_COMMAND", ""))
    server_url: str = field(default_factory=lambda: os.getenv("MCP_SERVER_URL", ""))

    splunk_host: str = field(default_factory=lambda: os.getenv("SPLUNK_HOST", "localhost"))
    splunk_port: str = field(default_factory=lambda: os.getenv("SPLUNK_PORT", "8089"))
    splunk_username: str = field(default_factory=lambda: os.getenv("SPLUNK_USERNAME", "admin"))
    splunk_password: str = field(default_factory=lambda: os.getenv("SPLUNK_PASSWORD", ""))
    splunk_token: str = field(default_factory=lambda: os.getenv("SPLUNK_TOKEN", ""))
    verify_ssl: bool = field(default_factory=lambda: _bool(os.getenv("SPLUNK_VERIFY_SSL"), False))


@dataclass(frozen=True)
class LLMConfig:
    """Connection settings for the reasoning model."""

    foundation_sec_base_url: str = field(
        default_factory=lambda: os.getenv("FOUNDATION_SEC_BASE_URL", "")
    )
    foundation_sec_api_key: str = field(
        default_factory=lambda: os.getenv("FOUNDATION_SEC_API_KEY", "")
    )
    foundation_sec_model: str = field(
        default_factory=lambda: os.getenv("FOUNDATION_SEC_MODEL", "foundation-sec-8b-instruct")
    )

    anthropic_api_key: str = field(default_factory=lambda: os.getenv("ANTHROPIC_API_KEY", ""))
    anthropic_model: str = field(
        default_factory=lambda: os.getenv("ANTHROPIC_MODEL", "claude-sonnet-4-6")
    )


@dataclass(frozen=True)
class Config:
    """Top level Sentinel configuration."""

    splunk_mode: str = field(default_factory=lambda: os.getenv("SPLUNK_MODE", "mock").lower())
    agent_max_steps: int = field(default_factory=lambda: int(os.getenv("AGENT_MAX_STEPS", "6")))
    web_host: str = field(default_factory=lambda: os.getenv("WEB_HOST", "0.0.0.0"))
    web_port: int = field(default_factory=lambda: int(os.getenv("WEB_PORT", "8000")))
    demo_step_delay_seconds: float = field(
        default_factory=lambda: float(os.getenv("DEMO_STEP_DELAY_SECONDS", "0.5"))
    )

    mcp: MCPConfig = field(default_factory=MCPConfig)
    llm: LLMConfig = field(default_factory=LLMConfig)

    @property
    def is_mock(self) -> bool:
        return self.splunk_mode != "live"


def get_config() -> Config:
    """Return a fresh :class:`Config` built from the current environment."""

    return Config()
