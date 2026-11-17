"""CLI configuration: ``~/.aios/config.toml`` plus environment overrides.

Defaults are loopback-only. A non-loopback API URL is refused unless the
operator explicitly opts in with ``AIOS_ALLOW_REMOTE=1``, because the core is
an unauthenticated local service.
"""

from __future__ import annotations

import ipaddress
import os
import tomllib
from dataclasses import dataclass, replace
from pathlib import Path
from urllib.parse import urlparse

DEFAULT_API_URL = "http://127.0.0.1:8000"
DEFAULT_TIMEOUT_S = 10.0
DEFAULT_HISTORY = "~/.aios/history"
DEFAULT_THEME = "default"


class ConfigError(ValueError):
    """The configuration cannot be used as written."""


@dataclass(frozen=True)
class Config:
    api_url: str = DEFAULT_API_URL
    timeout_s: float = DEFAULT_TIMEOUT_S
    theme: str = DEFAULT_THEME
    history_path: Path = Path(DEFAULT_HISTORY).expanduser()
    no_color: bool = False
    allow_remote: bool = False

    def with_overrides(self, **values: object) -> Config:
        clean = {key: value for key, value in values.items() if value is not None}
        return replace(self, **clean)


def default_config_path() -> Path:
    return Path(os.environ.get("AIOS_CONFIG", "~/.aios/config.toml")).expanduser()


def _flag(value: str | None) -> bool | None:
    if value is None or value == "":
        return None
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _float(value: str | None) -> float | None:
    if value is None or value == "":
        return None
    try:
        number = float(value)
    except ValueError as exc:
        raise ConfigError(f"expected a number, got {value!r}") from exc
    if number <= 0:
        raise ConfigError("timeout must be greater than zero")
    return number


def _read_toml(path: Path) -> dict:
    if not path.exists():
        return {}
    try:
        with path.open("rb") as handle:
            data = tomllib.load(handle)
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise ConfigError(f"cannot read {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise ConfigError(f"{path} must contain a TOML table")
    return data


def load_config(path: Path | None = None) -> Config:
    """Load the config file, then apply ``AIOS_*`` environment overrides."""
    config = Config()
    source = path or default_config_path()
    data = _read_toml(source)

    api = data.get("api") or {}
    ui = data.get("ui") or {}
    chat = data.get("chat") or {}
    if not all(isinstance(section, dict) for section in (api, ui, chat)):
        raise ConfigError(f"{source} sections must be tables")

    if "url" in api:
        config = replace(config, api_url=str(api["url"]))
    if "timeout_s" in api:
        timeout = _float(str(api["timeout_s"]))
        if timeout is not None:
            config = replace(config, timeout_s=timeout)
    if "theme" in ui:
        config = replace(config, theme=str(ui["theme"]))
    if "no_color" in ui:
        config = replace(config, no_color=bool(ui["no_color"]))
    if "history" in chat:
        config = replace(config, history_path=Path(str(chat["history"])).expanduser())

    config = config.with_overrides(
        api_url=os.environ.get("AIOS_API_URL") or None,
        timeout_s=_float(os.environ.get("AIOS_TIMEOUT_S")),
        theme=os.environ.get("AIOS_THEME") or None,
        no_color=_flag(os.environ.get("AIOS_NO_COLOR")),
        allow_remote=_flag(os.environ.get("AIOS_ALLOW_REMOTE")),
    )
    if os.environ.get("AIOS_HISTORY"):
        config = replace(config, history_path=Path(os.environ["AIOS_HISTORY"]).expanduser())

    return validate_config(config)


def validate_config(config: Config) -> Config:
    parsed = urlparse(config.api_url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ConfigError(f"api.url is not a valid http(s) URL: {config.api_url!r}")
    if not _is_loopback(parsed.hostname) and not config.allow_remote:
        raise ConfigError(
            "the AIOS core is unauthenticated and local-only; "
            "set AIOS_ALLOW_REMOTE=1 to allow a non-loopback API URL"
        )
    if config.timeout_s <= 0:
        raise ConfigError("timeout must be greater than zero")
    return config


def _is_loopback(host: str) -> bool:
    if host.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


__all__ = [
    "Config",
    "ConfigError",
    "DEFAULT_API_URL",
    "default_config_path",
    "load_config",
    "validate_config",
]
