"""Deterministic cleanup scanner.

The scanner — not the model — decides what is a candidate. The model may rank
or explain the result, but it cannot add a path, change a threshold, or claim
a file is unused.

Every candidate carries an identity (``dev``, ``ino``, ``mtime_ns``) that the
quarantine executor re-checks before touching it.
"""

from __future__ import annotations

import hashlib
import os
import stat as stat_module
from datetime import datetime, timedelta
from pathlib import Path

from aios.actions.models import Candidate, ScanResult
from aios.models.common import utcnow
from aios.observers.filesystem import SENSITIVE_PREFIXES

PROTECTED_PREFIXES = SENSITIVE_PREFIXES + (
    "/proc",
    "/sys",
    "/dev",
    "/run",
)

_SKIP_SUFFIXES = (".sock", ".socket", ".pid", ".lock")


def _is_protected(path: Path) -> bool:
    text = str(path)
    for prefix in PROTECTED_PREFIXES:
        if text == prefix or text.startswith(prefix.rstrip("/") + "/"):
            return True
    return False


def _is_excluded(path: Path, roots: tuple[Path, ...]) -> bool:
    return any(path == root or root in path.parents for root in roots)


def _open_inodes() -> set[tuple[int, int]]:
    """(dev, ino) of files currently open by any process.

    One pass over /proc, not one pass per candidate. Permission errors on
    other users' descriptors are ignored: an unreadable descriptor is not a
    reason to treat a file as safe.
    """
    open_files: set[tuple[int, int]] = set()
    try:
        pids = [entry for entry in os.scandir("/proc") if entry.name.isdigit()]
    except OSError:
        return open_files
    for pid in pids:
        try:
            fds = os.scandir(f"/proc/{pid.name}/fd")
        except OSError:
            continue
        with fds:
            for fd in fds:
                try:
                    st = os.stat(fd.path)
                except OSError:
                    continue
                open_files.add((st.st_dev, st.st_ino))
    return open_files


def _classify(path: Path) -> tuple[str, tuple[str, ...]]:
    text = str(path)
    lower = text.lower()
    suffix = path.suffix.lower()
    if "/.cache/" in lower or lower.endswith("/.cache") or "/cache/" in lower:
        return "cache entry", ("cache", "regenerable")
    if suffix in {".log", ".log.1", ".log.old"} or "/log/" in lower:
        return "log file", ("log", "regenerable")
    if "/tmp/" in lower or suffix in {".tmp", ".temp", ".swp", ".part"}:
        return "temporary file", ("temporary",)
    return "old file", ("old",)


def _candidate_id(path: Path, dev: int, ino: int, mtime_ns: int) -> str:
    material = f"{path}\0{dev}\0{ino}\0{mtime_ns}".encode()
    return "c-" + hashlib.sha256(material).hexdigest()[:16]


def scan_candidates(
    root: str | Path,
    *,
    min_age_days: int = 30,
    min_size_bytes: int = 0,
    max_candidates: int = 500,
    include_hidden: bool = False,
    exclude_roots: tuple[Path, ...] = (),
    now: datetime | None = None,
    uid: int | None = None,
) -> ScanResult:
    """Walk ``root`` and return bounded, deterministic candidates."""
    root_path = Path(root).resolve()
    if not root_path.is_dir():
        raise NotADirectoryError(f"not a directory: {root_path}")

    now = now or utcnow()
    cutoff_ns = int((now - timedelta(days=min_age_days)).timestamp() * 1_000_000_000)
    owner = os.getuid() if uid is None else uid
    root_dev = os.stat(root_path).st_dev
    excluded = tuple(p.resolve() for p in exclude_roots)
    open_files = _open_inodes()

    candidates: list[Candidate] = []
    total_bytes = 0
    scanned = 0
    skipped = 0
    truncated = False

    for current, dirs, files in os.walk(root_path, followlinks=False):
        current_path = Path(current)
        dirs[:] = sorted(
            d for d in dirs
            if (include_hidden or not d.startswith("."))
            and not _is_protected(current_path / d)
            and not _is_excluded((current_path / d).resolve(), excluded)
        )
        for name in sorted(files):
            if not include_hidden and name.startswith("."):
                skipped += 1
                continue
            path = current_path / name
            if _is_protected(path) or _is_excluded(path.resolve(), excluded):
                skipped += 1
                continue
            if name.endswith(_SKIP_SUFFIXES):
                skipped += 1
                continue
            try:
                st = os.lstat(path)
            except OSError:
                skipped += 1
                continue
            scanned += 1
            if not stat_module.S_ISREG(st.st_mode):
                skipped += 1
                continue
            if st.st_dev != root_dev:
                skipped += 1
                continue
            if st.st_nlink > 1:
                skipped += 1
                continue
            if st.st_uid != owner:
                skipped += 1
                continue
            if st.st_mtime_ns > cutoff_ns:
                skipped += 1
                continue
            if st.st_size < min_size_bytes:
                skipped += 1
                continue
            if (st.st_dev, st.st_ino) in open_files:
                skipped += 1
                continue
            try:
                if path.resolve().parent != root_path and root_path not in path.resolve().parents:
                    skipped += 1
                    continue
            except OSError:
                skipped += 1
                continue
            if len(candidates) >= max_candidates:
                truncated = True
                break

            reason, tags = _classify(path)
            candidates.append(
                Candidate(
                    candidate_id=_candidate_id(path, st.st_dev, st.st_ino, st.st_mtime_ns),
                    path=str(path),
                    dev=st.st_dev,
                    ino=st.st_ino,
                    size_bytes=st.st_size,
                    mtime_ns=st.st_mtime_ns,
                    mode=st.st_mode,
                    uid=st.st_uid,
                    reason=f"{reason} older than {min_age_days} days",
                    tags=tags,
                )
            )
            total_bytes += st.st_size
        if truncated:
            break

    return ScanResult(
        root=str(root_path),
        candidates=tuple(candidates),
        total=len(candidates),
        total_bytes=total_bytes,
        scanned_files=scanned,
        skipped=skipped,
        truncated=truncated,
        generated_at=now,
    )


__all__ = ["PROTECTED_PREFIXES", "scan_candidates"]
