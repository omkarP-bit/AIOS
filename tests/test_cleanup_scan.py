"""Deterministic cleanup scanner tests.

The scanner, not the model, decides what is a candidate. These tests pin the
filters that keep it from proposing something dangerous or ambiguous.
"""

from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from aios.actions.models import ScanResult
from aios.actions.scanner import _is_protected, scan_candidates
from aios.gateway import OSGateway, PreconditionFailed
from aios.models import make_request

NOW = datetime(2026, 1, 1, tzinfo=UTC)


def _write(path: Path, *, age_days: int = 100, size: int = 16) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"x" * size)
    stamp = (NOW - timedelta(days=age_days)).timestamp()
    os.utime(path, ns=(int(stamp * 1e9), int(stamp * 1e9)))
    return path


def test_old_regular_file_is_a_candidate(tmp_path: Path) -> None:
    target = _write(tmp_path / "old.log")
    result = scan_candidates(tmp_path, now=NOW)

    assert isinstance(result, ScanResult)
    assert result.total == 1
    candidate = result.candidates[0]
    assert candidate.path == str(target)
    assert candidate.size_bytes == 16
    assert candidate.candidate_id.startswith("c-")

    st = os.lstat(target)
    assert (candidate.dev, candidate.ino) == (st.st_dev, st.st_ino)
    assert (candidate.mtime_ns, candidate.mode, candidate.uid) == (
        st.st_mtime_ns,
        st.st_mode,
        st.st_uid,
    )


def test_recent_file_is_skipped(tmp_path: Path) -> None:
    _write(tmp_path / "fresh.log", age_days=1)
    result = scan_candidates(tmp_path, now=NOW, min_age_days=30)
    assert result.total == 0
    assert result.skipped == 1


def test_hidden_file_needs_an_explicit_flag(tmp_path: Path) -> None:
    _write(tmp_path / ".cache-entry")
    assert scan_candidates(tmp_path, now=NOW).total == 0
    assert scan_candidates(tmp_path, now=NOW, include_hidden=True).total == 1

    hidden_id = scan_candidates(tmp_path, now=NOW, include_hidden=True).candidates[0].candidate_id
    assert hidden_id


def test_symlink_is_never_a_candidate(tmp_path: Path) -> None:
    target = _write(tmp_path / "target.log")
    (tmp_path / "link.log").symlink_to(target)
    result = scan_candidates(tmp_path, now=NOW)
    assert [c.path for c in result.candidates] == [str(target)]


def test_hardlink_is_never_a_candidate(tmp_path: Path) -> None:
    target = _write(tmp_path / "multi.log")
    os.link(target, tmp_path / "multi-2.log")
    result = scan_candidates(tmp_path, now=NOW)
    assert result.total == 0


def test_open_file_is_never_a_candidate(tmp_path: Path) -> None:
    target = _write(tmp_path / "busy.log")
    with target.open("rb"):
        result = scan_candidates(tmp_path, now=NOW)
    assert result.total == 0


def test_file_below_the_size_floor_is_skipped(tmp_path: Path) -> None:
    _write(tmp_path / "tiny.log", size=4)
    _write(tmp_path / "large.log", size=4096)
    result = scan_candidates(tmp_path, now=NOW, min_size_bytes=1024)
    assert [c.path for c in result.candidates] == [str(tmp_path / "large.log")]


def test_quarantine_root_is_excluded(tmp_path: Path) -> None:
    _write(tmp_path / "keep" / "old.log")
    quarantine = tmp_path / "quarantine"
    _write(quarantine / "payload")
    result = scan_candidates(tmp_path, now=NOW, exclude_roots=(quarantine,))
    assert [c.path for c in result.candidates] == [str(tmp_path / "keep" / "old.log")]


def test_candidate_cap_truncates_deterministically(tmp_path: Path) -> None:
    for index in range(5):
        _write(tmp_path / f"f{index}.log")
    result = scan_candidates(tmp_path, now=NOW, max_candidates=2)
    assert result.total == 2
    assert result.truncated is True
    # Sorted walk order, so the same two files win on every run.
    assert [c.path for c in result.candidates] == [
        str(tmp_path / "f0.log"),
        str(tmp_path / "f1.log"),
    ]


def test_scan_is_repeatable(tmp_path: Path) -> None:
    _write(tmp_path / "a.log")
    _write(tmp_path / "sub" / "b.log")
    first = scan_candidates(tmp_path, now=NOW)
    second = scan_candidates(tmp_path, now=NOW)
    assert [c.model_dump() for c in first.candidates] == [
        c.model_dump() for c in second.candidates
    ]


def test_protected_prefixes_are_recognised() -> None:
    assert _is_protected(Path("/proc/1/mem"))
    assert _is_protected(Path("/sys/kernel"))
    assert _is_protected(Path("/etc/ssh/ssh_host_key"))
    assert not _is_protected(Path("/home/user/project/file.log"))


def test_non_directory_is_refused(tmp_path: Path) -> None:
    target = _write(tmp_path / "file.log")
    with pytest.raises(NotADirectoryError):
        scan_candidates(target, now=NOW)


# ---------------------------------------------------------------- gateway


@pytest.fixture
def gateway(proc_root: Path, sys_root: Path, tmp_path: Path) -> OSGateway:
    return OSGateway(proc_root=proc_root, sys_root=sys_root, quarantine_dir=tmp_path / "q")


def test_gateway_serves_scan_read_only(gateway: OSGateway, tmp_path: Path) -> None:
    _write(tmp_path / "work" / "old.log")
    request = make_request(
        "filesystem.cleanup_scan",
        params={"path": str(tmp_path / "work"), "min_age_days": 30},
    )
    observation = gateway.execute(request)
    assert observation.origin.value == "gateway"
    scan = observation.data
    assert scan.total == 1
    assert scan.candidates[0].path == str(tmp_path / "work" / "old.log")


def test_gateway_refuses_to_scan_a_file(gateway: OSGateway, tmp_path: Path) -> None:
    target = _write(tmp_path / "file.log")
    request = make_request(
        "filesystem.cleanup_scan", params={"path": str(target)}
    )
    with pytest.raises(PreconditionFailed):
        gateway.execute(request)
