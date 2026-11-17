"""Config tests: loopback defaults, env overrides, and clear failures."""

from __future__ import annotations

from pathlib import Path

import pytest

from aios.cli.config import (
    Config,
    ConfigError,
    load_config,
    validate_config,
)


def test_defaults_are_loopback() -> None:
    config = load_config(Path("/nonexistent/aios.toml"))
    assert config.api_url == "http://127.0.0.1:8000"
    assert config.timeout_s > 0
    assert config.history_path.name == "history"


def test_env_overrides(monkeypatch) -> None:
    monkeypatch.setenv("AIOS_API_URL", "http://127.0.0.1:9000")
    monkeypatch.setenv("AIOS_TIMEOUT_S", "2.5")
    monkeypatch.setenv("AIOS_NO_COLOR", "1")
    config = load_config(Path("/nonexistent/aios.toml"))
    assert config.api_url == "http://127.0.0.1:9000"
    assert config.timeout_s == 2.5
    assert config.no_color is True


def test_remote_url_is_refused_by_default() -> None:
    with pytest.raises(ConfigError) as caught:
        validate_config(Config(api_url="http://10.0.0.5:8000"))
    assert "AIOS_ALLOW_REMOTE" in str(caught.value)


def test_remote_url_allowed_with_opt_in(monkeypatch) -> None:
    monkeypatch.setenv("AIOS_ALLOW_REMOTE", "1")
    config = load_config(Path("/nonexistent/aios.toml"))
    assert config.api_url == "http://127.0.0.1:8000"
    validate_config(Config(api_url="http://10.0.0.5:8000", allow_remote=True))


def test_ipv6_loopback_is_allowed() -> None:
    validate_config(Config(api_url="http://[::1]:8000"))


def test_bad_scheme_is_refused() -> None:
    with pytest.raises(ConfigError):
        validate_config(Config(api_url="ftp://127.0.0.1:8000"))


def test_bad_timeout_is_refused(monkeypatch) -> None:
    monkeypatch.setenv("AIOS_TIMEOUT_S", "soon")
    with pytest.raises(ConfigError):
        load_config(Path("/nonexistent/aios.toml"))


def test_toml_file_is_read(tmp_path) -> None:
    path = tmp_path / "config.toml"
    path.write_text(
        '[api]\nurl = "http://127.0.0.1:8123"\ntimeout_s = 3\n'
        "[ui]\nno_color = true\n"
        '[chat]\nhistory = "~/aios-test-history"\n',
        encoding="utf-8",
    )
    config = load_config(path)
    assert config.api_url == "http://127.0.0.1:8123"
    assert config.timeout_s == 3.0
    assert config.no_color is True
    assert config.history_path.name == "aios-test-history"
