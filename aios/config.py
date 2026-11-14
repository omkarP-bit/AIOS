"""Runtime configuration for AIOS.

Every root the gateway reads from is injectable so that the whole stack can be
tested against fixture trees instead of the live host. That is a security
property, not just a testing convenience: a test must never be able to reach
the real filesystem by accident, and a gateway must never be able to reach
outside the roots it was configured with.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

PACKAGE_ROOT = Path(__file__).resolve().parent


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="AIOS_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        protected_namespaces=(),
    )

    database_url: str = "postgresql+psycopg2://aios@localhost/aios"

    api_host: str = "127.0.0.1"
    api_port: int = 8000

    # Read-only roots. The gateway refuses to read outside these.
    proc_root: Path = Path("/proc")
    sys_root: Path = Path("/sys")

    policy_dir: Path = PACKAGE_ROOT / "policies"

    # Day 4+. Empty means no OPA server; the packaged Rego policy is then
    # evaluated locally with the OPA binary. If neither can run, the engine
    # denies. It must never silently fail open.
    opa_url: str = ""
    opa_timeout_s: float = 2.0
    opa_binary: str = "opa"

    # Day 5+. Groq is an external provider; it is disabled unless both
    # AIOS_ALLOW_EXTERNAL_MODEL and AIOS_GROQ_API_KEY are set. The local
    # Ollama path remains available for deployments that can run a model.
    model_provider: str = "groq"
    allow_external_model: bool = False
    groq_api_key: str = ""
    groq_base_url: str = "https://api.groq.com/openai/v1"
    groq_model: str = "llama-3.1-8b-instant"
    groq_timeout_s: float = 30.0
    groq_max_tokens: int = 1024
    groq_temperature: float = 0.0

    ollama_url: str = "http://127.0.0.1:11434"
    ollama_model: str = "qwen2.5:3b-instruct-q4_K_M"
    ollama_timeout_s: float = 60.0

    # Hard ceiling on any single file the gateway will read.
    max_read_bytes: int = Field(default=1_048_576, ge=1)
    # Directory listing cap.
    max_dir_entries: int = Field(default=2000, ge=1)

    # Mutation reference path. Quarantine must be on the same filesystem as
    # the approved targets; cross-device moves are refused.
    quarantine_dir: Path = Field(
        default_factory=lambda: Path.home() / ".local" / "state" / "aios" / "quarantine"
    )
    # HMAC key for plan approval tokens. Empty means an ephemeral key, so
    # tokens cannot survive a restart; set it for multi-process deployments.
    approval_secret: str = ""
    approval_ttl_s: int = Field(default=900, ge=30, le=86400)

    @property
    def opa_enabled(self) -> bool:
        return bool(self.opa_url)

    @property
    def groq_enabled(self) -> bool:
        return self.allow_external_model and bool(self.groq_api_key)


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()


def reset_settings_cache() -> None:
    """Test hook — drop the cached settings so env changes take effect."""
    get_settings.cache_clear()
