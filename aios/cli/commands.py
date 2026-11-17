"""Typer commands for the AIOS terminal client."""

from __future__ import annotations

import functools
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from typing import Annotated, Any

import typer
from rich.live import Live
from rich.text import Text

import aios
from aios.ai.providers import provider_status
from aios.cli.assistant import Assistant
from aios.cli.chat import run_chat
from aios.cli.errors import CliError, UsageError
from aios.cli.state import AppState, get_state
from aios.cli.ui.render import (
    render_actions,
    render_audit,
    render_cpu,
    render_error,
    render_memory,
    render_network,
    render_processes,
    render_provider,
    render_security,
    render_status,
)

app = typer.Typer(
    add_completion=True,
    no_args_is_help=True,
    rich_markup_mode=None,
    help=(
        "AIOS terminal client. It reads the local control core over HTTP and "
        "never executes anything itself. Use `aios --json` for machine output."
    ),
)

SORTS = {"cpu", "mem", "pid", "name"}


def guarded(fn: Callable[..., Any]) -> Callable[..., Any]:
    @functools.wraps(fn)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        state = get_state()
        try:
            return fn(*args, **kwargs)
        except UsageError as exc:
            state.console.print(render_error(exc.message, next_step=exc.next_step))
            raise typer.Exit(exc.exit_code) from exc
        except CliError as exc:
            state.console.print(render_error(exc.message, next_step=exc.next_step))
            raise typer.Exit(exc.exit_code) from exc
        except KeyboardInterrupt:
            state.console.print(Text("cancelled", style="aios.dim"))
            raise typer.Exit(130) from None
        except typer.Exit:
            raise
        except Exception as exc:  # never show a traceback by default
            state.console.print(
                render_error(
                    "The CLI hit an unexpected error.",
                    next_step="Retry with --verbose to see details, or run `aios status`.",
                )
            )
            if state.verbose:
                state.console.print_exception()
            raise typer.Exit(1) from exc

    return wrapper


@contextmanager
def spinner(state: AppState, label: str) -> Iterator[None]:
    if state.json_output or not state.console.is_terminal:
        yield
        return
    with state.console.status(Text(label, style="aios.dim"), spinner="dots"):
        yield


def run_view(
    state: AppState,
    *,
    label: str,
    fetch: Callable[[], Any],
    render: Callable[[Any], Any],
    to_json: Callable[[Any], Any] | None = None,
) -> None:
    if state.watch_s <= 0:
        with spinner(state, label):
            payload = fetch()
        if state.json_output:
            state.print_json((to_json or _identity)(payload))
        else:
            state.console.print(render(payload))
        return

    if state.json_output:
        try:
            while True:
                state.print_json((to_json or _identity)(fetch()))
                time.sleep(state.watch_s)
        except KeyboardInterrupt:
            return

    with spinner(state, label):
        initial = fetch()
    if not state.console.is_terminal:
        # No alternate-screen to repaint; print a fresh view per interval so
        # redirected output stays useful.
        state.console.print(render(initial))
        try:
            while True:
                time.sleep(state.watch_s)
                state.console.print(render(fetch()))
        except KeyboardInterrupt:
            return
    try:
        with Live(render(initial), console=state.console, refresh_per_second=1) as live:
            while True:
                time.sleep(state.watch_s)
                live.update(render(fetch()))
    except KeyboardInterrupt:
        return


def _identity(value: Any) -> Any:
    return value


@app.command()
@guarded
def status() -> None:
    """Dashboard: host, CPU, memory, top processes, network, services.

    Examples:
      aios status
      aios --json status | jq .health.services
      aios --watch 5 status
    """
    state = get_state()

    def fetch() -> dict[str, Any]:
        client = state.client
        return {
            "status": client.status(),
            "cpu": client.cpu(0.25),
            "memory": client.memory(),
            "processes": client.processes(limit=5, sort_by="cpu"),
            "network": client.network(limit=200),
            "health": client.health(),
        }

    run_view(
        state,
        label="reading host state…",
        fetch=fetch,
        render=lambda payload: render_status(
            payload["status"],
            payload["cpu"],
            payload["memory"],
            payload["processes"],
            payload["network"],
            payload["health"],
        ),
    )


@app.command()
@guarded
def cpu(
    interval: float = typer.Option(0.25, "--interval", min=0.0, max=5.0, help="Sample interval."),
) -> None:
    """CPU bars, load averages, per-core usage, and frequencies.

    Example: aios cpu --interval 0.5
    """
    state = get_state()
    run_view(
        state,
        label="sampling CPU…",
        fetch=lambda: state.client.cpu(interval),
        render=render_cpu,
    )


@app.command()
@guarded
def memory() -> None:
    """Memory and swap usage.

    Example: aios memory
    """
    state = get_state()
    run_view(state, label="reading memory…", fetch=state.client.memory, render=render_memory)


@app.command()
@guarded
def processes(
    sort: str = typer.Option("cpu", "--sort", help="cpu, mem, pid, or name."),
    limit: int = typer.Option(20, "--limit", min=1, max=1000, help="Rows to show."),
    name_filter: str = typer.Option("", "--filter", help="Substring of the process name."),
) -> None:
    """Process table with PID, name, state, CPU%, and RSS.

    Examples:
      aios processes --sort mem --limit 10
      aios processes --filter postgres
    """
    state = get_state()
    if sort not in SORTS:
        raise UsageError(f"unknown sort {sort!r}", next_step="Use --sort cpu, mem, pid, or name.")
    run_view(
        state,
        label="listing processes…",
        fetch=lambda: state.client.processes(
            limit=limit, sort_by=sort, name_filter=name_filter or None
        ),
        render=lambda payload: render_processes(payload, sort_by=sort, name_filter=name_filter),
    )


@app.command()
@guarded
def network(
    listening: bool = typer.Option(False, "--listening", help="Only show listening sockets."),
) -> None:
    """TCP/UDP connections with local/remote endpoints and owning PID.

    Example: aios network --listening
    """
    state = get_state()
    run_view(
        state,
        label="reading connections…",
        fetch=lambda: state.client.network(listening_only=listening),
        render=lambda payload: render_network(payload, listening_only=listening),
    )


@app.command()
@guarded
def audit(
    denied: bool = typer.Option(False, "--denied", help="Only denied actions."),
    limit: int = typer.Option(50, "--limit", min=1, max=1000, help="Rows to show."),
) -> None:
    """Audit trail: action, risk, decision, state, reason, time.

    Examples:
      aios audit --denied
      aios --json audit --limit 10
    """
    state = get_state()
    run_view(
        state,
        label="reading audit ledger…",
        fetch=lambda: state.client.audit(limit=limit, denied=denied),
        render=lambda entries: render_audit(entries, denied_only=False),
        to_json=lambda entries: {"entries": entries, "count": len(entries)},
    )


@app.command()
@guarded
def actions(
    denied: bool = typer.Option(False, "--denied", help="Only denied actions."),
    limit: int = typer.Option(50, "--limit", min=1, max=1000, help="Rows to show."),
) -> None:
    """Decided actions, optionally only denials.

    Example: aios actions --denied
    """
    state = get_state()
    run_view(
        state,
        label="reading decisions…",
        fetch=lambda: state.client.audit(limit=limit, denied=denied),
        render=lambda entries: render_actions(entries, denied_only=False),
        to_json=lambda entries: {"entries": entries, "count": len(entries)},
    )


@app.command()
@guarded
def security() -> None:
    """Security summary: blocked/confirmed counts, services, last events.

    Example: aios security
    """
    state = get_state()
    run_view(
        state,
        label="reading security summary…",
        fetch=state.client.security_summary,
        render=render_security,
    )


@app.command()
@guarded
def model() -> None:
    """Show the model provider, model, and readiness (the key stays hidden).

    Examples:
      aios model
      aios --json model
    """
    state = get_state()
    status = provider_status()
    if state.json_output:
        state.print_json(status)
    else:
        state.console.print(render_provider(status))


@app.command()
@guarded
def ask(
    question: Annotated[list[str], typer.Argument(help="Question in natural language.")],
) -> None:
    """Ask one question; propose, decide, confirm, and answer.

    The model can propose an action. The core decides. A CONFIRM card asks
    first and defaults to No.

    Examples:
      aios ask "how much memory is free?"
      aios ask "what is in /tmp"
    """
    state = get_state()
    text = " ".join(question).strip()
    if not text:
        raise UsageError("the question is empty")
    assistant = Assistant(state)
    result = assistant.run(text, execute_allowed=True, render=not state.json_output)
    if state.json_output:
        state.print_json(
            {
                "question": result.question,
                "plan": _plan_json(result),
                "verdict": result.verdict,
                "confirmed": result.confirmed,
                "denied": result.denied,
                "answer": result.answer,
                "error": result.error.message if result.error else None,
            }
        )
    if result.error is not None:
        if not state.json_output:
            assistant.render_error(result.error)
        raise typer.Exit(result.error.exit_code)
    if result.answer and not state.json_output:
        assistant.render_answer(result.answer)
    if result.denied:
        raise typer.Exit(3)


@app.command()
@guarded
def chat() -> None:
    """Interactive AI session with history, slash commands, and a toolbar.

    Esc+Enter (or Alt+Enter) sends; Ctrl+C cancels; Ctrl+D exits.
    Slash commands: /help /clear /status /history /audit /actions /session /json /exit
    """
    state = get_state()
    code = run_chat(state)
    if code:
        raise typer.Exit(code)


@app.command()
def version() -> None:
    """Print the client and protocol version."""
    state = get_state()
    if state.json_output:
        state.print_json({"aios": aios.__version__})
    else:
        state.console.print(Text(f"aios {aios.__version__}", style="aios.title"))


def _plan_json(result: Any) -> dict[str, Any] | None:
    plan = result.plan
    if plan is None:
        return None
    return {
        "provider": plan.provider,
        "model": plan.model,
        "external": plan.external,
        "prompt_hash": plan.prompt_hash,
        "request": plan.request.to_payload() if plan.request else None,
        "reason": plan.reason,
        "answer": plan.answer,
    }


__all__ = ["app"]
