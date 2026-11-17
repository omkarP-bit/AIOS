"""Interactive prompt_toolkit REPL for ``aios chat``.

Slash commands are handled locally and never sent to the model. A failed turn
prints the error and keeps the session and its history alive.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from prompt_toolkit import PromptSession
from prompt_toolkit.history import FileHistory
from prompt_toolkit.key_binding import KeyBindings
from rich.text import Text

from aios.cli.assistant import Assistant
from aios.cli.client import ensure_parent
from aios.cli.errors import CliError
from aios.cli.state import AppState
from aios.cli.ui.render import (
    render_actions,
    render_audit,
    render_error,
    render_history,
    render_session,
    render_status,
)
from aios.cli.ui.sanitize import sanitize_inline

HELP = """\
Commands handled locally (never sent to the model):
  /help      show this help
  /clear     clear the conversation and the screen
  /status    system dashboard
  /history   recent turns in this session
  /audit     recent audit rows
  /actions   recent decisions
  /session   session id, model, service health, trust mode
  /json      toggle machine-readable turn output
  /exit      leave the session

Enter inserts a newline. Esc+Enter (Alt+Enter) sends. Ctrl+C cancels the
current prompt or request. Ctrl+D exits.
"""


@dataclass
class ChatHealth:
    api: str = "unknown"
    engine: str = "unknown"
    opa: str = "unknown"
    ledger: str = "unknown"

    @property
    def text(self) -> str:
        return f"api {self.api} · engine {self.engine} · opa {self.opa} · db {self.ledger}"


@dataclass
class ChatState:
    turns: list[dict[str, Any]] = field(default_factory=list)
    health: ChatHealth = field(default_factory=ChatHealth)
    model: str = "unavailable"


def run_chat(state: AppState) -> int:
    assistant = Assistant(state)
    chat = ChatState(model=_model_label(assistant))
    _refresh_health(state, chat)
    session = _make_session(state, assistant, chat)

    state.console.print(
        Text(
            "AIOS chat. Slash commands are local. Esc+Enter sends. Ctrl+D exits.",
            style="aios.dim",
        )
    )

    while True:
        try:
            line = session.prompt("aios› ")
        except KeyboardInterrupt:
            state.console.print(Text("cancelled", style="aios.dim"))
            continue
        except EOFError:
            state.console.print(Text("session closed", style="aios.dim"))
            return 0

        text = line.strip()
        if not text:
            continue
        if text.startswith("/"):
            if not _slash(text, state, assistant, chat):
                return 0
            continue

        chat.turns.append({"question": text, "decision": None, "answer": None})
        try:
            result = assistant.run(text, execute_allowed=True, render=not state.json_output)
        except KeyboardInterrupt:
            state.console.print(Text("cancelled", style="aios.dim"))
            continue
        except CliError as exc:
            assistant.render_error(exc)
            chat.turns[-1]["answer"] = f"error: {exc.message}"
            _refresh_health(state, chat)
            continue

        if result.error is not None:
            assistant.render_error(result.error)
        if result.answer and not state.json_output:
            assistant.render_answer(result.answer)
        if state.json_output:
            state.print_json(
                {
                    "session_id": assistant.session_id,
                    "question": result.question,
                    "blocks": result.blocks,
                    "verdict": result.verdict,
                    "confirmed": result.confirmed,
                    "denied": result.denied,
                    "answer": result.answer,
                }
            )

        decision = (result.verdict or {}).get("decision")
        chat.turns[-1]["decision"] = decision or "NO ACTION"
        chat.turns[-1]["answer"] = result.answer
        assistant.history.append(("user", text))
        assistant.history.append(("assistant", result.answer or result.summary or "no answer"))
        _refresh_health(state, chat)


def _make_session(state: AppState, assistant: Assistant, chat: ChatState) -> PromptSession:
    history_path = state.config.history_path
    try:
        ensure_parent(history_path)
        history = FileHistory(str(history_path))
    except OSError:
        history = None
    bindings = _bindings()

    def toolbar() -> list[tuple[str, str]]:
        return [
            ("fg:#5f87af bold", " aios "),
            ("", f" {sanitize_inline(assistant.session_id, max_length=24)} "),
            ("fg:#888888", f"model {sanitize_inline(chat.model, max_length=40)} "),
            ("", f"· {sanitize_inline(chat.health.text, max_length=90)} "),
            ("fg:#888888", "· trust T3 "),
        ]

    return PromptSession(
        history=history,
        multiline=True,
        key_bindings=bindings,
        bottom_toolbar=toolbar,
    )


def _bindings() -> KeyBindings:
    bindings = KeyBindings()

    @bindings.add("escape", "enter")
    def _send(event: Any) -> None:
        event.current_buffer.validate_and_handle()

    return bindings


def _model_label(assistant: Assistant) -> str:
    try:
        provider = assistant.provider()
    except CliError:
        return "unavailable"
    return f"{provider.name}:{provider.model}"


def _refresh_health(state: AppState, chat: ChatState) -> None:
    try:
        health = state.client.health()
        services = health.get("services") or {}
        chat.health = ChatHealth(
            api=str(services.get("api", "unknown")),
            engine=str(services.get("engine", "unknown")),
            opa=str(services.get("opa", "unknown")),
            ledger=str(services.get("ledger", "unknown")),
        )
    except CliError:
        chat.health = ChatHealth(
            api="unavailable", engine="unavailable", opa="unavailable", ledger="unavailable"
        )


def _slash(
    text: str,
    state: AppState,
    assistant: Assistant,
    chat: ChatState,
) -> bool:
    command = text.split(maxsplit=1)[0].lower()
    if command in {"/exit", "/quit"}:
        state.console.print(Text("session closed", style="aios.dim"))
        return False
    if command == "/help":
        state.console.print(Text(HELP, style="aios.dim"))
        return True
    if command == "/clear":
        assistant.history.clear()
        chat.turns.clear()
        state.console.clear()
        state.console.print(Text("conversation cleared", style="aios.dim"))
        return True
    if command == "/json":
        state.json_output = not state.json_output
        state.console.no_color = state.json_output or state.no_color
        state.console.print(
            Text(f"json output {'on' if state.json_output else 'off'}", style="aios.dim")
        )
        return True
    if command == "/session":
        state.console.print(
            render_session(
                session_id=assistant.session_id,
                model=chat.model,
                health=chat.health.text,
                trust="T3 (ai/user) · untrusted output sanitized",
                turns=len(chat.turns),
            )
        )
        return True
    if command == "/history":
        state.console.print(render_history(chat.turns))
        return True
    if command in {"/status", "/audit", "/actions"}:
        _local_view(state, command)
        return True
    state.console.print(
        render_error(
            f"Unknown command {command}.",
            next_step="Use /help to see the local slash commands.",
        )
    )
    return True


def _local_view(state: AppState, command: str) -> None:
    try:
        if command == "/status":
            payload = {
                "status": state.client.status(),
                "cpu": state.client.cpu(0.25),
                "memory": state.client.memory(),
                "processes": state.client.processes(limit=5, sort_by="cpu"),
                "network": state.client.network(limit=200),
                "health": state.client.health(),
            }
            state.console.print(
                render_status(
                    payload["status"],
                    payload["cpu"],
                    payload["memory"],
                    payload["processes"],
                    payload["network"],
                    payload["health"],
                )
            )
        elif command == "/audit":
            state.console.print(render_audit(state.client.audit(limit=25)))
        else:
            state.console.print(render_actions(state.client.audit(limit=25)))
    except CliError as exc:
        state.console.print(render_error(exc.message, next_step=exc.next_step))


__all__ = ["run_chat"]
