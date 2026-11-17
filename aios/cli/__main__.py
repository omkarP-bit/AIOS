"""Entry point for the ``aios`` console script.

Global flags are accepted anywhere on the command line:

    aios status --watch 5
    aios --json audit --denied
    aios ask "how much memory is free?" --no-color

They are removed before Typer sees the arguments, so a subcommand never has to
declare them. Everything after ``--`` is left untouched.
"""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass, field

from aios.cli.commands import app
from aios.cli.config import ConfigError, load_config
from aios.cli.errors import EXIT_USAGE
from aios.cli.state import build_state, get_state, set_state

_WATCH_PREFIXES = ("--watch=",)


@dataclass
class GlobalFlags:
    argv: list[str] = field(default_factory=list)
    json_output: bool = False
    no_color: bool = False
    verbose: bool = False
    watch_s: int = 0
    help_requested: bool = False


def extract_global_flags(argv: list[str]) -> GlobalFlags:
    flags = GlobalFlags()
    index = 0
    passthrough = False
    while index < len(argv):
        arg = argv[index]
        if passthrough:
            flags.argv.append(arg)
            index += 1
            continue
        if arg == "--":
            passthrough = True
            flags.argv.append(arg)
            index += 1
            continue
        if arg == "--json":
            flags.json_output = True
        elif arg in {"--no-color", "--no-colour"}:
            flags.no_color = True
        elif arg == "--verbose":
            flags.verbose = True
        elif arg == "--watch":
            value = argv[index + 1] if index + 1 < len(argv) else ""
            flags.watch_s = _parse_watch(value)
            index += 1
        elif arg.startswith(_WATCH_PREFIXES):
            flags.watch_s = _parse_watch(arg.split("=", 1)[1])
        elif arg in {"--help", "-h"}:
            flags.help_requested = True
            flags.argv.append(arg)
        else:
            flags.argv.append(arg)
        index += 1
    return flags


def _parse_watch(value: str) -> int:
    try:
        seconds = int(value)
    except (TypeError, ValueError) as exc:
        raise ConfigError(f"--watch expects whole seconds, got {value!r}") from exc
    if seconds < 0:
        raise ConfigError("--watch cannot be negative")
    return seconds


def main(argv: list[str] | None = None) -> None:
    args = list(sys.argv[1:] if argv is None else argv)
    try:
        flags = extract_global_flags(args)
        config = load_config()
    except ConfigError as exc:
        print(f"aios: {exc}", file=sys.stderr)
        raise SystemExit(EXIT_USAGE) from None

    no_color = flags.no_color or bool(os.environ.get("NO_COLOR"))
    set_state(
        build_state(
            config,
            json_output=flags.json_output,
            no_color=no_color,
            verbose=flags.verbose,
            watch_s=flags.watch_s,
        )
    )

    try:
        app(args=flags.argv, prog_name="aios", standalone_mode=True)
    except SystemExit:
        raise
    except Exception as exc:  # last-resort guard: never a raw traceback
        state = get_state()
        state.console.print(
            "aios: unexpected error; rerun with --verbose for details.",
            markup=False,
            highlight=False,
        )
        if flags.verbose:
            state.console.print_exception()
        raise SystemExit(1) from exc


if __name__ == "__main__":
    main()


__all__ = ["GlobalFlags", "extract_global_flags", "main"]
