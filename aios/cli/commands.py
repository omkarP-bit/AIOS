"""Typer commands for the AIOS terminal client."""

from __future__ import annotations

import functools
import re
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
from aios.cli.client import raise_for_verdict
from aios.cli.errors import CliError, UsageError
from aios.cli.state import AppState, get_state
from aios.cli.ui.render import (
    render_actions,
    render_audit,
    render_cleanup_plan,
    render_cpu,
    render_diagnose,
    render_disk,
    render_error,
    render_memory,
    render_network,
    render_plan,
    render_processes,
    render_provider,
    render_result,
    render_security,
    render_status,
    render_verdict,
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

_EXT_OPTION = typer.Option([], "--ext", help="Only these extensions; repeatable.")

_AGE = re.compile(r"^(\d+)\s*([dwm]?)$", re.IGNORECASE)
_SIZE = re.compile(r"^(\d+(?:\.\d+)?)\s*([kmgt]?i?b?)$", re.IGNORECASE)
_SIZE_UNITS = {
    "": 1,
    "b": 1,
    "k": 1_000,
    "kb": 1_000,
    "ki": 1024,
    "kib": 1024,
    "m": 1_000_000,
    "mb": 1_000_000,
    "mi": 1 << 20,
    "mib": 1 << 20,
    "g": 1_000_000_000,
    "gb": 1_000_000_000,
    "gi": 1 << 30,
    "gib": 1 << 30,
    "t": 1_000_000_000_000,
    "tb": 1_000_000_000_000,
    "ti": 1 << 40,
    "tib": 1 << 40,
}


def _age_days(value: str) -> int:
    match = _AGE.match(value.strip())
    if not match:
        raise UsageError(
            f"invalid age {value!r}",
            next_step="Use a whole number of days, for example --older-than 30d.",
        )
    amount = int(match.group(1))
    unit = (match.group(2) or "d").lower()
    return amount * {"d": 1, "w": 7, "m": 30}[unit]


def _size_bytes(value: str) -> int:
    match = _SIZE.match(value.strip())
    if not match:
        raise UsageError(
            f"invalid size {value!r}",
            next_step="Use bytes or a unit such as 10M, 1GiB, or 500KB.",
        )
    unit = match.group(2).lower()
    if unit not in _SIZE_UNITS:
        raise UsageError(f"unknown size unit in {value!r}", next_step="Use B, K, M, G, or T.")
    return int(float(match.group(1)) * _SIZE_UNITS[unit])


def _confirm(state: AppState, question: str) -> bool:
    """Ask a question whose default is always No.

    EOF, Ctrl-C, and non-interactive input all mean No. Nothing is inferred
    from a filename, a plan, or model output.
    """
    try:
        answer = state.console.input(f"{question} [y/N]: ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        return False
    return answer in {"y", "yes"}


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
def disk() -> None:
    """Disk capacity for each mounted filesystem.

    Example: aios disk
    """
    state = get_state()
    run_view(state, label="reading disk usage…", fetch=state.client.disk, render=render_disk)


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
def diagnose(
    limit: int = typer.Option(200, "--limit", min=1, max=5000, help="Orphan rows to cap."),
    top: int = typer.Option(5, "--top", min=0, max=50, help="Top CPU/memory rows."),
    orphans: bool = typer.Option(True, "--orphans/--no-orphans", help="Include orphans."),
) -> None:
    """Diagnose zombies, orphans, and top CPU/memory processes.

    A zombie is already dead and cannot be signalled; the parent must reap it.

    Example: aios diagnose
    """
    state = get_state()
    run_view(
        state,
        label="diagnosing processes…",
        fetch=lambda: state.client.diagnose(limit=limit, include_orphans=orphans, top_n=top),
        render=render_diagnose,
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
def plan(
    action: str = typer.Argument(..., help="process.signal or network.prefer."),
    pid: int | None = typer.Option(None, "--pid", help="Process id for process.signal."),
    signal: str = typer.Option("TERM", "--signal", help="TERM, KILL, HUP, INT, QUIT, STOP, CONT."),
    connection: str = typer.Option("", "--connection", help="NetworkManager profile id or UUID."),
    intent: str = typer.Option("", "--intent", help="Short reason recorded in the plan."),
) -> None:
    """Build a core-hashed plan and show every step before any mutation.

    Examples:
      aios plan process.signal --pid 4242 --signal TERM
      aios plan network.prefer --connection "Home Wi-Fi"
    """
    state = get_state()
    if action == "process.signal":
        if pid is None:
            raise UsageError("process.signal needs --pid", next_step="Pass --pid N.")
        params: dict[str, Any] = {"pid": pid, "signal": signal.upper()}
    elif action == "network.prefer":
        if not connection:
            raise UsageError(
                "network.prefer needs --connection",
                next_step="Pass a NetworkManager profile id or UUID.",
            )
        params = {"connection": connection}
    else:
        raise UsageError(
            f"{action} is not a plan action",
            next_step="Use process.signal or network.prefer.",
        )
    with spinner(state, "building plan…"):
        payload = state.client.build_plan(action, params, intent=intent or None)
    if state.json_output:
        state.print_json(payload)
        return
    state.console.print(render_plan(payload))
    state.console.print(
        Text(
            "Nothing has run. To approve this exact hash, use `aios apply`.",
            style="aios.dim",
        )
    )


@app.command()
@guarded
def apply(
    plan_id: str = typer.Argument(..., help="Plan id printed by `aios plan`."),
    plan_hash: str = typer.Option(..., "--plan-hash", help="Exact hash being approved."),
    step_id: str = typer.Option("step-1", "--step-id", help="Approved step to run."),
    action: str = typer.Option("", "--action", help="Expected action name."),
) -> None:
    """Approve one core-built plan by its exact hash and apply it.

    Typing the exact plan hash is the approval. The core checks it against its
    own stored plan, applies it once, and records the outcome.

    Example:
      aios apply plan-abc123 --plan-hash sha256:... --step-id step-1
    """
    state = get_state()
    with spinner(state, "applying approved plan…"):
        _status, verdict = state.client.apply_plan(
            plan_id, plan_hash, step_id, action=action or None
        )
    if state.json_output:
        state.print_json(verdict)
        return
    state.console.print(render_verdict(verdict, target=str(verdict.get("target") or "")))
    data = verdict.get("data")
    if data is not None:
        state.console.print(
            render_result(
                data,
                source=verdict.get("source"),
                trust_domain=verdict.get("data_trust") or verdict.get("trust_domain"),
            )
        )


@app.command()
@guarded
def clean(
    directory: str = typer.Argument(
        ..., help="Absolute directory to scan. There is deliberately no default."
    ),
    older_than: str = typer.Option("30d", "--older-than", help="Minimum age, e.g. 30d, 2w."),
    ext: list[str] = _EXT_OPTION,
    min_size: str = typer.Option("0", "--min-size", help="Minimum size, e.g. 10M or 1048576."),
    max_results: int = typer.Option(500, "--max-results", min=1, max=5000),
    approve: bool = typer.Option(
        False, "--approve", help="Ask for approval after showing the plan (default answer No)."
    ),
    yes: bool = typer.Option(
        False, "--yes", help="Answer Yes without a prompt; only meaningful with --approve."
    ),
) -> None:
    """Propose a reversible cleanup plan from deterministic criteria.

    The scan is read-only and never runs by default. Files are selected only by
    directory, age, size, extension, and result cap -- never by name or content.
    Approval and trashing are separate, hash-bound steps; files move to
    reversible quarantine, never to permanent deletion.

    Examples:
      aios clean /var/log --older-than 30d --ext .log --min-size 10M
      aios clean ~/Downloads --older-than 90d --approve
    """
    state = get_state()
    days = _age_days(older_than)
    size = _size_bytes(min_size)
    extensions = [e if e.startswith(".") else f".{e}" for e in ext]
    with spinner(state, "building cleanup plan…"):
        payload = state.client.propose_cleanup(
            directory,
            min_age_days=days,
            min_size_bytes=size,
            extensions=extensions,
            max_results=max_results,
        )
    plan_data = payload["plan"]
    plan_id = str(payload["plan_id"])
    plan_hash = str(payload["plan_hash"])
    if isinstance(payload.get("verdict"), dict):
        raise_for_verdict(payload["verdict"], "/plans")

    if state.json_output:
        state.print_json({**payload, "dry_run": not approve, "approved": False})
    else:
        state.console.print(render_cleanup_plan(plan_data))

    if not approve:
        if not state.json_output:
            state.console.print(
                Text(
                    "Dry run only. Nothing was moved. Re-run with --approve to review and confirm.",
                    style="aios.dim",
                )
            )
        return

    if state.json_output and not yes:
        raise UsageError(
            "Non-interactive approval requires --yes with --approve.",
            next_step="Use --approve --yes in scripts, or drop --json to answer the prompt.",
        )
    if not yes and not _confirm(
        state, f"Move {plan_data.get('file_count', 0)} files to quarantine?"
    ):
        if not state.json_output:
            state.console.print(Text("Cancelled. Nothing was moved.", style="aios.dim"))
        return

    with spinner(state, "approving exact plan…"):
        state.client.approve_cleanup(plan_id, plan_hash)
    with spinner(state, "moving files to quarantine…"):
        result = state.client.trash_cleanup(plan_id)
    if state.json_output:
        state.print_json({**result, "plan_id": plan_id, "plan_hash": plan_hash, "approved": True})
        return
    state.console.print(render_verdict(result["verdict"]))
    verdict_data = (result["verdict"].get("result") or {}).get("data") or {}
    action_id = result["verdict"].get("action_id") or verdict_data.get("action_id") or ""
    state.console.print(
        Text(
            "Files moved to reversible quarantine. To undo this action, run: aios restore "
            + str(action_id),
            style="aios.dim",
        )
    )


@app.command()
@guarded
def restore(
    action_id: str = typer.Argument(..., help="Action id printed by `aios clean --approve`."),
) -> None:
    """Restore every file moved by one trash action, using its audit id."""
    state = get_state()
    with spinner(state, "restoring files…"):
        result = state.client.restore_action(action_id)
    if state.json_output:
        state.print_json(result)
        return
    state.console.print(Text(f"Restored action {action_id}.", style="aios.dim"))


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
    Slash commands: /help /clear /status /history /audit /actions /session /details /json /exit
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
