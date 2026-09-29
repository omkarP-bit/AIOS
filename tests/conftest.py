"""Shared pytest fixtures.

Tests run against fixture procfs/sysfs trees, never the live host, so a
failing test can never act on the developer's real machine.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from aios.config import Settings, reset_settings_cache

FIXTURE_ROOT = Path(__file__).parent / "fixtures"


@pytest.fixture
def proc_root() -> Path:
    root = FIXTURE_ROOT / "proc"
    if not root.exists():
        pytest.skip("procfs fixtures not generated")
    return root


@pytest.fixture
def sys_root() -> Path:
    root = FIXTURE_ROOT / "sys"
    if not root.exists():
        pytest.skip("sysfs fixtures not generated")
    return root


@pytest.fixture
def live_proc_root() -> Path:
    return Path("/proc")


@pytest.fixture
def live_sys_root() -> Path:
    return Path("/sys")


@pytest.fixture
def tmp_workdir(tmp_path: Path) -> Path:
    root = tmp_path / "work"
    root.mkdir()
    return root


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    reset_settings_cache()
    cfg = Settings(
        database_url="sqlite+pysqlite:///:memory:",
        proc_root=FIXTURE_ROOT / "proc",
        sys_root=FIXTURE_ROOT / "sys",
        policy_dir=tmp_path / "policies",
        opa_url="",
    )
    yield cfg
    reset_settings_cache()


@pytest.fixture
def real_uid() -> int:
    return os.getuid()
