"""Process-wide state shared by the Typer commands."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

from rich.console import Console

from aios.cli.client import CoreClient, client_from_config
from aios.cli.config import Config
from aios.cli.ui.theme import AIOS_THEME


@dataclass
class AppState:
    config: Config
    client: CoreClient
    console: Console
    json_output: bool = False
    no_color: bool = False
    verbose: bool = False
    watch_s: int = 0
    extra: dict[str, Any] = field(default_factory=dict)

    @property
    def interactive(self) -> bool:
        return not self.json_output and self.console.is_terminal

    def print_json(self, payload: Any) -> None:
        text = json.dumps(payload, indent=2, sort_keys=True, default=str)
        # json.dumps escapes control characters, so untrusted strings cannot
        # emit a terminal escape sequence here.
        self.console.print(text, markup=False, highlight=False, soft_wrap=True)


_STATE: AppState | None = None


def build_state(
    config: Config,
    *,
    json_output: bool = False,
    no_color: bool = False,
    verbose: bool = False,
    watch_s: int = 0,
    client: CoreClient | None = None,
) -> AppState:
    console = Console(
        theme=AIOS_THEME,
        no_color=no_color or config.no_color or json_output,
        highlight=False,
        soft_wrap=False,
    )
    return AppState(
        config=config,
        client=client or client_from_config(config),
        console=console,
        json_output=json_output,
        no_color=no_color,
        verbose=verbose,
        watch_s=watch_s,
    )


def set_state(state: AppState) -> AppState:
    global _STATE
    _STATE = state
    return state


def get_state() -> AppState:
    if _STATE is None:
        raise RuntimeError("CLI state was not initialised")
    return _STATE


__all__ = ["AppState", "build_state", "get_state", "set_state"]
