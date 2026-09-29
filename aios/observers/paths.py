"""Rooted path resolution for procfs/sysfs readers.

Two jobs:

1. Testability — every reader takes a root, so tests run against fixture trees
   instead of the live host.
2. Containment — ``resolve_under`` guarantees a resolved path is still inside
   the root it was given. This blocks symlink escape (a fixture or a hostile
   ``/proc`` entry that points at ``/etc/shadow`` stops here, at T2, before
   anything reaches the AI).
"""

from __future__ import annotations

from pathlib import Path, PurePosixPath


class PathEscapeError(PermissionError):
    """Raised when a path resolves outside its configured root."""


def resolve_under(root: Path, *parts: str | PurePosixPath) -> Path:
    """Join ``parts`` onto ``root`` and verify the result stays inside it.

    ``..`` segments, absolute components, and symlinks that leave the root are
    all rejected. Nonexistent paths are allowed (the caller decides whether a
    missing file is an error); containment is checked on the resolved prefix.
    """
    root_resolved = root.resolve()
    candidate = root_resolved
    for part in parts:
        text = str(part)
        if not text or text == ".":
            continue
        if text.startswith("/"):
            # An absolute component would silently discard the root.
            raise PathEscapeError(f"absolute path component not allowed: {text!r}")
        candidate = candidate / PurePosixPath(text)

    # strict=False: for nonexistent paths, resolve() still normalises and
    # resolves the existing prefix, which is what we need to check containment.
    resolved = candidate.resolve()
    if resolved != root_resolved and root_resolved not in resolved.parents:
        raise PathEscapeError(f"{resolved} escapes root {root_resolved}")
    return resolved


def read_text(path: Path, max_bytes: int = 1 << 20) -> str:
    """Read a small text file with a hard byte ceiling.

    Kernel pseudo-files report size 0, so the limit is enforced on the bytes
    actually read rather than on ``stat``.
    """
    chunks: list[str] = []
    total = 0
    with path.open("r", encoding="utf-8", errors="replace") as fh:
        while True:
            chunk = fh.read(64 * 1024)
            if not chunk:
                break
            total += len(chunk)
            if total > max_bytes:
                raise ValueError(f"{path} exceeds read limit of {max_bytes} bytes")
            chunks.append(chunk)
    return "".join(chunks)


def read_int(path: Path, default: int | None = None) -> int | None:
    """Read a single integer, tolerating transient ESRCH-style absence."""
    try:
        return int(read_text(path, 4096).strip())
    except (OSError, ValueError):
        return default
