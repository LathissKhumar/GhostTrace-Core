"""GhostTrace environment configuration with startup validation.

Validates all required environment variables at import time and provides
typed access to configuration values. Fail-fast with clear error messages
if critical variables are missing.
"""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass, field
from pathlib import Path

from dotenv import load_dotenv

# Load .env before reading any variables
load_dotenv()

APP_VERSION = "1.1.0"


def _get_env(key: str, default: str | None = None, required: bool = False) -> str:
    """Read an environment variable, failing fast if required and missing."""
    value = os.environ.get(key, default or "")
    if required and not value:
        print(
            f"\n[GhostTrace FATAL] Missing required environment variable: {key}\n"
            f"  Set it in your .env file or export it before starting the server.\n"
            f"  See .env.example for all available options.\n",
            file=sys.stderr,
        )
        sys.exit(1)
    return value


def _parse_bool(value: str) -> bool:
    """Parse a string to boolean (true/1/yes → True)."""
    return value.lower() in ("true", "1", "yes")


def _parse_cors_origins(value: str) -> list[str]:
    """Parse CORS_ORIGINS into a list, stripping whitespace."""
    if not value or value.strip() == "*":
        return ["*"]
    return [origin.strip() for origin in value.split(",") if origin.strip()]


@dataclass(frozen=True)
class Settings:
    """Immutable application settings derived from environment variables."""

    # LLM Provider
    llm_provider: str = field(default_factory=lambda: _get_env("LLM_PROVIDER", "groq"))
    groq_api_key: str = field(default_factory=lambda: _get_env("GROQ_API_KEY"))
    groq_model: str = field(
        default_factory=lambda: _get_env("GROQ_MODEL", "llama-3.3-70b-versatile")
    )
    anthropic_api_key: str = field(
        default_factory=lambda: _get_env("ANTHROPIC_API_KEY")
    )
    ollama_base_url: str = field(
        default_factory=lambda: _get_env("OLLAMA_BASE_URL", "http://localhost:11434/v1")
    )
    ollama_model: str = field(
        default_factory=lambda: _get_env("OLLAMA_MODEL", "llama3.1:8b")
    )

    # Server
    host: str = field(default_factory=lambda: _get_env("HOST", "0.0.0.0"))
    port: int = field(
        default_factory=lambda: int(_get_env("PORT", "8000"))
    )
    reload: bool = field(
        default_factory=lambda: _parse_bool(_get_env("RELOAD", "false"))
    )

    # CORS
    cors_origins: list[str] = field(
        default_factory=lambda: _parse_cors_origins(_get_env("CORS_ORIGINS", "*"))
    )

    # Rate limiting
    rate_limit_per_minute: int = field(
        default_factory=lambda: int(_get_env("RATE_LIMIT_PER_MINUTE", "60"))
    )

    # Upload limits
    max_upload_size_bytes: int = field(
        default_factory=lambda: int(_get_env("MAX_UPLOAD_SIZE_MB", "10")) * 1024 * 1024
    )

    # Paths
    cases_dir: str = field(
        default_factory=lambda: _get_env("CASES_DIR", "./cases")
    )

    # Logging
    log_level: str = field(
        default_factory=lambda: _get_env("LOG_LEVEL", "INFO").upper()
    )
    log_format: str = field(
        default_factory=lambda: _get_env("LOG_FORMAT", "json")
    )


def validate_provider_settings() -> None:
    """Validate that the selected LLM provider has the required credentials.

    Prints warnings for missing keys (non-fatal) but fails if the provider
    itself is invalid.
    """
    valid_providers = {"groq", "anthropic", "ollama"}
    provider = settings.llm_provider

    if provider not in valid_providers:
        print(
            f"\n[GhostTrace FATAL] Invalid LLM_PROVIDER: '{provider}'\n"
            f"  Must be one of: {', '.join(sorted(valid_providers))}\n",
            file=sys.stderr,
        )
        sys.exit(1)

    if provider == "groq" and not settings.groq_api_key:
        print(
            "[GhostTrace WARNING] GROQ_API_KEY not set. "
            "Get a free key at https://console.groq.com",
            file=sys.stderr,
        )
    elif provider == "anthropic" and not settings.anthropic_api_key:
        print(
            "[GhostTrace WARNING] ANTHROPIC_API_KEY not set. "
            "Agent endpoints will return HTTP 503 until configured.",
            file=sys.stderr,
        )


# Singleton settings instance — import this from anywhere
settings = Settings()

# Validate on import
validate_provider_settings()
