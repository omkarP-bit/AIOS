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
    )

    database_url: str = "postgresql+psycopg2://aios@localhost/aios"

    api_host: str = "127.0.0.1"
    api_port: int = 8000

    # Read-only roots. The gateway refuses to read outside these.
    proc_root: Path = Path("/proc")
    sys_root: Path = Path("/sys")

    policy_dir: Path = PACKAGE_ROOT / "policies"

    # Day 4+. Empty means "no OPA configured" and the security engine runs in
    # local-policy mode only. It must never silently fail open.
    opa_url: str = ""
    opa_timeout_s: float = 2.0

    # Day 5+.
    ollama_url: str = "http://127.0.0.1:11434"
    ollama_model: str = "qwen2.5:3b-instruct-q4_K_M"
    ollama_timeout_s: float = 60.0

    # Hard ceiling on any single file the gateway will read.
    max_read_bytes: int = Field(default=1_048_576, ge=1)
    # Directory listing cap.
    max_dir_entries: int = Field(default=2000, ge=1)

    @property
    def opa_enabled(self) -> bool:
        return bool(self.opa_url)


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()


def reset_settings_cache() -> None:
    """Test hook — drop the cached settings so env changes take effect."""
    get_settings.cache_clear()
