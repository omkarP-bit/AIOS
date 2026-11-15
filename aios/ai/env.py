"""Minimal .env loader shared by the planner and its HTTP client.

The Go core reads .env itself. The planner does the same so one file configures
both processes without an extra dependency. Existing environment variables win.
"""

from __future__ import annotations

import os
from pathlib import Path

_LOADED = False


def load_dotenv(path: str | os.PathLike[str] = ".env") -> None:
    global _LOADED
    if _LOADED:
        return
    _LOADED = True
    try:
        lines = Path(path).read_text(encoding="utf-8").splitlines()
    except OSError:
        return
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        if key.startswith("export "):
            key = key[len("export ") :].strip()
        value = value.strip().strip("\"'")
        if key and key not in os.environ:
            os.environ[key] = value


__all__ = ["load_dotenv"]
