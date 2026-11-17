"""Minimal .env loader shared by the planner and its HTTP client.

The Go core reads .env itself. The planner does the same so one file configures
both processes without an extra dependency. Existing environment variables win.

The file is resolved independently of the caller's working directory, because
a provider silently falling back to local Ollama just because the shell was in
another directory is a confusing failure. The order is:

1. an explicit ``path`` argument,
2. ``$AIOS_ENV_FILE``,
3. ``~/.aios/.env``,
4. the project root ``.env`` next to this package,
5. ``./.env``.
"""

from __future__ import annotations

import os
from pathlib import Path

_LOADED = False


def dotenv_path(path: str | os.PathLike[str] | None = None) -> Path:
    """Resolve the one .env file to read, without touching the environment."""
    if path is not None:
        return Path(path).expanduser()
    override = os.environ.get("AIOS_ENV_FILE", "").strip()
    if override:
        return Path(override).expanduser()
    state = Path("~/.aios/.env").expanduser()
    if state.is_file():
        return state
    # An editable checkout keeps .env at the project root: aios/ai/env.py is
    # two parents below it. Resolving from __file__ keeps the provider stable
    # even when the command runs from a subdirectory.
    project = Path(__file__).resolve().parents[2] / ".env"
    if project.is_file():
        return project
    return Path(".env")


def load_dotenv(path: str | os.PathLike[str] | None = None) -> None:
    global _LOADED
    if _LOADED:
        return
    _LOADED = True
    try:
        lines = dotenv_path(path).read_text(encoding="utf-8").splitlines()
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


__all__ = ["dotenv_path", "load_dotenv"]
