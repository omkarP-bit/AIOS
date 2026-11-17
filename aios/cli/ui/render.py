"""Render API data, verdicts, and chat turns with Rich.

Every value that came from the system or the model passes through
:func:`aios.cli.ui.sanitize.sanitize`. Renderers build ``Text`` objects and
tables; untrusted strings are never interpolated into Rich markup.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any

from rich import box
from rich.console import Group
from rich.markdown import Markdown
from rich.panel import Panel
from rich.progress_bar import ProgressBar
from rich.table import Table
from rich.text import Text

from aios.cli.ui.sanitize import sanitize_block, sanitize_inline
from aios.cli.ui.theme import (
    decision_badge,
    decision_style,
    risk_badge,
    risk_style,
    state_badge,
    state_style,
    status_badge,
    trust_badge,
)

STATE_ORDER = [
    "PROPOSED",
    "VALIDATED",
    "AUTHORIZED",
    "EXECUTED",
    "OBSERVED",
    "COMPLETED",
]

DENIAL_TEXT = {
    "not_in_protocol": "This action is not part of the approved protocol.",
    "forbidden_action": "This action is permanently forbidden.",
    "invalid_params": "The request was malformed, so it was refused.",
    "scope_mismatch": "The target is outside the granted scope.",
    "capability_missing": "No capability grant covers this action and target.",
    "capability_revoked": "The capability covering this action was revoked.",
    "capability_expired": "The capability covering this action expired.",
    "risk_too_high": "The risk is too high for this path.",
    "policy_deny": "Policy denied this request.",
    "policy_unavailable": "The policy engine is unavailable, so AIOS failed closed.",
    "gateway_refused": "The read-only gateway refused this request.",
    "gateway_error": "The gateway could not complete this read.",
    "confirmation_required": "This action needs your confirmation.",
    "plan_required": "This change needs an approved plan.",
    "approval_invalid": "The approval token is not valid for this plan.",
    "approval_expired": "The approval token expired.",
    "plan_mismatch": "The plan changed after it was approved.",
    "target_changed": "The target changed after approval, so it was refused.",
    "executor_refused": "The executor refused this mutation.",
    "limit_exceeded": "The request exceeds the plan limits.",
    "plan_replayed": "This plan was already applied; it cannot be replayed.",
    "cross_device": "The source and quarantine are on different filesystems.",
    "internal_error": "The core hit an internal error and refused the action.",
    "confirmation_not_allowed": "This action cannot be confirmed interactively.",
}


SHORT_DENIAL = {
    "not_in_protocol": "not in protocol",
    "forbidden_action": "forbidden",
    "invalid_params": "invalid params",
    "scope_mismatch": "scope mismatch",
    "capability_missing": "no capability",
    "capability_revoked": "grant revoked",
    "capability_expired": "grant expired",
    "risk_too_high": "risk too high",
    "policy_deny": "policy deny",
    "policy_unavailable": "policy down",
    "gateway_refused": "gateway refused",
    "gateway_error": "gateway error",
    "confirmation_required": "needs approval",
    "plan_required": "plan required",
    "approval_invalid": "approval invalid",
    "approval_expired": "approval expired",
    "plan_mismatch": "plan changed",
    "target_changed": "target changed",
    "executor_refused": "executor refused",
    "limit_exceeded": "limit exceeded",
    "plan_replayed": "plan replayed",
    "cross_device": "cross-device move",
    "internal_error": "internal error",
}


def denial_explanation(code: object) -> str:
    key = str(code or "").strip()
    return DENIAL_TEXT.get(key, "Denied by policy for an unspecified reason.")


def short_denial(code: object) -> str:
    """A table-sized label for a denial code."""
    key = str(code or "").strip()
    return SHORT_DENIAL.get(key, key or "-")


# --- small helpers ---------------------------------------------------------


def _value(data: Any, *keys: str, default: Any = None) -> Any:
    current = data
    for key in keys:
        if not isinstance(current, dict):
            return default
        current = current.get(key)
    return default if current is None else current


def _text(value: Any, *, max_length: int = 256, style: str | None = None) -> Text:
    return Text(sanitize_inline(value, max_length=max_length), style=style or "")


def _block(value: Any, *, max_length: int = 8000, style: str | None = None) -> Text:
    return Text(sanitize_block(value, max_length=max_length), style=style or "")


def _number(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _human_bytes(value: Any) -> str:
    try:
        size = float(value)
    except (TypeError, ValueError):
        return "-"
    if size <= 0:
        return "-"
    units = ["B", "KiB", "MiB", "GiB", "TiB"]
    index = 0
    while size >= 1024 and index < len(units) - 1:
        size /= 1024
        index += 1
    return f"{size:.1f} {units[index]}"


def _memory_bytes(kilobytes: Any) -> str:
    try:
        return _human_bytes(float(kilobytes) * 1024)
    except (TypeError, ValueError):
        return "-"


def _duration(seconds: Any) -> str:
    try:
        total = int(float(seconds))
    except (TypeError, ValueError):
        return "-"
    if total < 0:
        return "-"
    days, rest = divmod(total, 86_400)
    hours, rest = divmod(rest, 3_600)
    minutes, secs = divmod(rest, 60)
    if days:
        return f"{days}d {hours:02d}:{minutes:02d}"
    if hours:
        return f"{hours}h {minutes:02d}m"
    if minutes:
        return f"{minutes}m {secs:02d}s"
    return f"{secs}s"


def _percent(value: Any) -> float:
    return max(0.0, min(100.0, _number(value)))


def _bar(value: Any, width: int = 22, style: str = "green") -> ProgressBar:
    return ProgressBar(
        total=100,
        completed=_percent(value),
        width=width,
        style="grey23",
        complete_style=style,
        finished_style=style,
    )


def _percent_text(value: Any) -> Text:
    return Text(f"{_percent(value):5.1f}%", style="aios.title")


def _bar_line(
    value: Any,
    *,
    width: int = 22,
    style: str = "green",
    suffix: tuple[str, str] | None = None,
) -> Table:
    """A progress bar plus its numeric label, side by side."""
    grid = Table.grid(padding=(0, 1))
    grid.add_column(no_wrap=True)
    grid.add_column(overflow="fold")
    label = _percent_text(value)
    if suffix:
        label = Text.assemble(label, suffix)
    grid.add_row(_bar(value, width=width, style=style), label)
    return grid


def _local_datetime(value: Any) -> datetime | None:
    """Parse an API timestamp and convert it to the operator's local zone."""
    if not isinstance(value, str):
        return None
    text = value.strip()
    if not text:
        return None
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone()


def _timestamp(value: Any, *, time_only: bool = False) -> Text:
    local = _local_datetime(value)
    if local is not None:
        text = local.strftime("%H:%M:%S" if time_only else "%m-%d %H:%M:%S")
        return Text(text, style="aios.dim")
    # Unknown shapes stay visible verbatim, minus control characters.
    text = sanitize_inline(value, max_length=32)
    if "T" in text:
        text = text.replace("T", " ", 1)
    if time_only and len(text) >= 19:
        text = text[11:19]
    # The table is width-constrained; keep month-day and time but drop the
    # year. Exact timestamps remain available in --json output.
    elif len(text) >= 19 and text[4] == "-" and text[7] == "-":
        text = text[5:19]
    return Text(text or "-", style="aios.dim")


def _table(title: str | None = None, caption: str | None = None) -> Table:
    table = Table(
        title=title,
        caption=caption,
        box=box.SIMPLE_HEAD,
        header_style="aios.dim",
        title_style="aios.title",
        caption_style="aios.dim",
        pad_edge=False,
    )
    return table


def _lifecycle(state: object, decision: object) -> Text:
    state = str(state or "").upper()
    decision = str(decision or "").upper()
    if decision == "DENY" or state == "DENIED":
        return Text("PROPOSED → VALIDATED → DENIED", style="red")
    if decision == "CONFIRM" or state == "CONFIRM":
        return Text("PROPOSED → VALIDATED → CONFIRM", style="yellow")
    if state not in STATE_ORDER:
        return Text(state or "-", style=state_style(state))
    index = STATE_ORDER.index(state)
    text = Text()
    for position, step in enumerate(STATE_ORDER[: index + 1]):
        if position:
            text.append(" → ", style="dim")
        text.append(step, style=state_style(step))
    return text


def _service_badge(name: str, value: object) -> Text:
    label = sanitize_inline(value, max_length=24)
    return Text.assemble(
        (f"{name} ", "aios.dim"),
        status_badge(label),
    )


def _services_line(services: dict[str, Any]) -> Text:
    line = Text()
    for position, name in enumerate(("api", "engine", "opa", "ledger")):
        if position:
            line.append("  ")
        line.append_text(_service_badge(name.upper(), services.get(name, "unknown")))
    return line


# --- observation views -----------------------------------------------------


def render_status(
    status: dict[str, Any],
    cpu: dict[str, Any],
    memory: dict[str, Any],
    processes: dict[str, Any],
    network: dict[str, Any],
    health: dict[str, Any],
    security: dict[str, Any] | None = None,
) -> Panel:
    grid = Table.grid(padding=(0, 2))
    grid.add_column(justify="right", style="aios.dim", no_wrap=True)
    grid.add_column(overflow="fold")

    grid.add_row("host", _text(_value(status, "hostname", default="unknown")))
    grid.add_row("kernel", _text(_value(status, "kernel", default="-")))
    grid.add_row("uptime", Text(_duration(_value(status, "uptime_s"))))
    grid.add_row("cores", Text(str(_value(status, "logical_cores", default="-"))))

    percent = _value(cpu, "percent", default={}) or {}
    load = " ".join(
        f"{_number(_value(cpu, key, default=0)):.2f}"
        for key in ("load_average_1m", "load_average_5m", "load_average_15m")
    )
    grid.add_row(
        "cpu",
        _bar_line(
            percent.get("total"),
            suffix=(f"   load {load}", "aios.dim"),
        ),
    )
    grid.add_row(
        "memory",
        _bar_line(
            memory.get("used_percent"),
            style="yellow",
            suffix=(
                f"   {_memory_bytes(memory.get('used_kb'))}"
                f" / {_memory_bytes(memory.get('total_kb'))}",
                "aios.dim",
            ),
        ),
    )

    top = _table()
    for column, justify in (
        ("PID", "right"),
        ("NAME", "left"),
        ("CPU%", "right"),
        ("MEM", "right"),
    ):
        top.add_column(column, justify=justify, no_wrap=(column != "NAME"))
    for process in list(_value(processes, "processes", default=[]) or [])[:5]:
        cpu_percent = process.get("cpu_percent")
        top.add_row(
            Text(str(process.get("pid", "-"))),
            _text(process.get("name"), max_length=32),
            Text("-" if cpu_percent is None else f"{_number(cpu_percent):.1f}"),
            Text(_human_bytes(process.get("rss_bytes"))),
        )

    summary = _value(network, "summary", default={}) or {}
    total = summary.get("total", _value(network, "total", default="-"))
    listening = _value(summary, "by_state", default={}) or {}
    connections = Text.assemble(
        (str(total), "aios.title"),
        " connections",
        (f"  ({listening.get('LISTEN', 0)} listening)", "aios.dim"),
    )

    services = (security or {}).get("services") or health.get("services") or {}
    body = Group(
        grid,
        Text(""),
        Text("Top processes", style="aios.title"),
        top,
        Group(Text.assemble(("network  ", "aios.dim"), connections)),
        Group(Text.assemble(("services ", "aios.dim"), _services_line(services))),
    )
    return Panel(
        body,
        title="AIOS status",
        title_align="left",
        border_style="aios.panel",
    )


def render_cpu(cpu: dict[str, Any]) -> Panel:
    percent = cpu.get("percent", {}) or {}
    header = Table.grid(padding=(0, 2))
    header.add_column(justify="right", style="aios.dim")
    header.add_column()
    header.add_row(
        "total",
        _bar_line(percent.get("total"), width=30),
    )
    for label in ("user", "system", "idle"):
        header.add_row(label, Text(f"{_number(percent.get(label)):.1f}%"))

    cores = cpu.get("per_core", []) or []
    table = _table()
    table.add_column("CORE", no_wrap=True)
    table.add_column("USAGE", justify="right")
    table.add_column("", no_wrap=True)
    table.add_column("FREQ", justify="right")
    frequencies = {str(item.get("cpu")): item for item in (cpu.get("frequencies", []) or [])}
    for core in cores:
        name = sanitize_inline(core.get("name"), max_length=16) or "-"
        usage = core.get("percent")
        frequency = frequencies.get(name, {})
        khz = frequency.get("khz")
        table.add_row(
            Text(name),
            Text("-" if usage is None else f"{_number(usage):5.1f}%"),
            _bar(usage or 0, width=18, style="green"),
            Text("-" if khz is None else f"{_number(khz) / 1_000_000:.2f} GHz"),
        )

    body: Any = header
    if cores:
        body = Group(header, Text(""), table)
    return Panel(body, title="CPU", title_align="left", border_style="aios.panel")


def render_memory(memory: dict[str, Any]) -> Panel:
    grid = Table.grid(padding=(0, 2))
    grid.add_column(justify="right", style="aios.dim")
    grid.add_column()
    grid.add_row(
        "used",
        _bar_line(memory.get("used_percent"), width=30, style="yellow"),
    )
    grid.add_row(
        "total",
        Text(_memory_bytes(memory.get("total_kb")), style="aios.title"),
    )
    grid.add_row("used", Text(_memory_bytes(memory.get("used_kb"))))
    grid.add_row("available", Text(_memory_bytes(memory.get("available_kb"))))
    swap_total = _number(memory.get("swap_total_kb"))
    if swap_total > 0:
        grid.add_row(
            "swap",
            _bar_line(
                memory.get("swap_used_percent"),
                width=30,
                style="magenta",
                suffix=(
                    f"   {_memory_bytes(memory.get('swap_used_kb'))}"
                    f" / {_memory_bytes(memory.get('swap_total_kb'))}",
                    "aios.dim",
                ),
            ),
        )
    return Panel(grid, title="Memory", title_align="left", border_style="aios.panel")


def render_processes(
    data: dict[str, Any],
    *,
    sort_by: str = "cpu",
    name_filter: str = "",
) -> Table | Panel:
    processes = data.get("processes", []) or []
    if not processes:
        return Panel(
            Text("No processes matched.", style="aios.dim"),
            title="Processes",
            border_style="aios.panel",
            title_align="left",
        )
    table = _table(
        title="Processes",
        caption=f"sort={sanitize_inline(sort_by, max_length=16)}"
        + (f"  filter={sanitize_inline(name_filter, max_length=32)}" if name_filter else ""),
    )
    for column, justify in (
        ("PID", "right"),
        ("NAME", "left"),
        ("STATE", "left"),
        ("CPU%", "right"),
        ("MEM", "right"),
    ):
        table.add_column(column, justify=justify, no_wrap=(column != "NAME"))
    for process in processes:
        cpu_percent = process.get("cpu_percent")
        table.add_row(
            Text(str(process.get("pid", "-"))),
            _text(process.get("name"), max_length=40),
            _text(process.get("state"), max_length=8),
            Text("-" if cpu_percent is None else f"{_number(cpu_percent):.1f}"),
            Text(_human_bytes(process.get("rss_bytes"))),
        )
    return table


def render_diagnose(data: dict[str, Any]) -> Panel:
    """Read-only process diagnosis: zombies, orphans, and top resource users.

    A zombie is never presented as killable; the recommendation names the
    parent that must reap it.
    """
    zombies = data.get("zombies") or []
    orphans = data.get("orphans") or []
    grid = Table.grid(padding=(0, 3))
    grid.add_column(justify="right", style="aios.dim")
    grid.add_column()
    grid.add_row("scanned", Text(str(data.get("total_scanned", 0))))
    grid.add_row(
        "zombies",
        Text(str(len(zombies)), style="bold red" if zombies else "aios.dim"),
    )
    grid.add_row("orphans", Text(str(len(orphans))))

    def findings(rows: list[dict[str, Any]], title: str) -> Table | Panel:
        if not rows:
            return Panel(Text("None.", style="aios.dim"), title=title, title_align="left")
        table = _table(title=title)
        for column, justify in (
            ("PID", "right"),
            ("PPID", "right"),
            ("NAME", "left"),
            ("PARENT", "left"),
            ("REASON", "left"),
        ):
            table.add_column(column, justify=justify, no_wrap=(column != "REASON"))
        for row in rows:
            table.add_row(
                Text(str(row.get("pid", "-"))),
                Text(str(row.get("ppid", "-"))),
                _text(row.get("name"), max_length=24),
                _text(row.get("parent_name") or "-", max_length=24),
                _text(row.get("recommendation") or row.get("reason"), max_length=80),
            )
        return table

    body = Group(
        grid,
        Text(""),
        findings(zombies, "Zombies · parent must reap"),
        findings(orphans, "Orphans · alive and reparented"),
    )
    return Panel(body, title="Process diagnosis", title_align="left", border_style="aios.panel")


def render_network(data: dict[str, Any], *, listening_only: bool = False) -> Table | Panel:
    connections = data.get("connections", []) or []
    if not connections:
        return Panel(
            Text("No connections matched.", style="aios.dim"),
            title="Network",
            border_style="aios.panel",
            title_align="left",
        )
    table = _table(
        title="Network",
        caption="listening only" if listening_only else None,
    )
    for column, justify in (
        ("PROTO", "left"),
        ("LOCAL", "left"),
        ("REMOTE", "left"),
        ("STATE", "left"),
        ("PID", "right"),
    ):
        table.add_column(column, justify=justify, no_wrap=True)
    for connection in connections:
        family = str(connection.get("family") or "").rstrip("6").upper()
        local = _address(connection.get("local_address"), connection.get("local_port"))
        remote = _address(connection.get("remote_address"), connection.get("remote_port"))
        pids = connection.get("pids") or []
        table.add_row(
            Text(sanitize_inline(family, max_length=8) or "-"),
            Text(local),
            Text(remote),
            _text(connection.get("state"), max_length=16),
            Text(str(pids[0]) if pids else "-"),
        )
    return table


def _address(host: Any, port: Any) -> str:
    if not host:
        return "-"
    if port is None:
        return sanitize_inline(host, max_length=40)
    return f"{sanitize_inline(host, max_length=40)}:{port}"


# --- audit and security ----------------------------------------------------


def _audit_table(
    entries: list[dict[str, Any]], *, title: str, compact: bool = False
) -> Table | Panel:
    if not entries:
        return Panel(
            Text("No audit entries.", style="aios.dim"),
            title=title,
            border_style="aios.panel",
            title_align="left",
        )
    table = _table(title=title)
    table.add_column("ACTION", no_wrap=True, max_width=18 if compact else 20)
    table.add_column("RISK", no_wrap=True)
    table.add_column("DECISION", no_wrap=True)
    if not compact:
        table.add_column("STATE", no_wrap=True, max_width=10)
    table.add_column("REASON", overflow="ellipsis", max_width=16 if compact else 18, no_wrap=True)
    table.add_column("TIME", no_wrap=True)
    dates = {
        local.date().isoformat()
        for entry in entries
        if (local := _local_datetime(entry.get("at"))) is not None
    }
    single_date = dates.pop() if len(dates) == 1 else ""
    if single_date:
        table.title = f"{title} · {single_date}"
    for entry in entries:
        denial = entry.get("denial_reason")
        reason = short_denial(denial) if compact else (denial if denial else "-")
        row = [
            _text(entry.get("action"), max_length=18 if compact else 20),
            risk_badge(entry.get("risk")),
            decision_badge(entry.get("decision")),
        ]
        if not compact:
            row.append(state_badge(entry.get("state")))
        row.append(_text(reason, max_length=16 if compact else 18))
        row.append(_timestamp(entry.get("at"), time_only=bool(single_date)))
        table.add_row(*row)
    return table


def render_audit(
    entries: list[dict[str, Any]],
    *,
    title: str = "Audit",
    denied_only: bool = False,
) -> Table | Panel:
    if denied_only:
        entries = [entry for entry in entries if entry.get("decision") == "DENY"]
    return _audit_table(entries, title=title)


def render_actions(entries: list[dict[str, Any]], *, denied_only: bool = False) -> Table | Panel:
    if denied_only:
        entries = [entry for entry in entries if entry.get("decision") == "DENY"]
    else:
        entries = [entry for entry in entries if entry.get("decision")]
    return _audit_table(entries, title="Actions")


def render_security(summary: dict[str, Any]) -> Panel:
    counts = summary.get("counts", {}) or {}
    services = summary.get("services", {}) or {}
    grid = Table.grid(padding=(0, 3))
    grid.add_column(justify="right", style="aios.dim")
    grid.add_column()
    grid.add_row(
        "events",
        Text.assemble(
            (str(counts.get("total", 0)), "aios.title"),
            " total",
        ),
    )
    grid.add_row(
        "blocked",
        Text.assemble(
            (str(counts.get("denied", 0)), "red"),
            " denied",
            (f" · {counts.get('confirmed', 0)} confirmed", "aios.dim"),
        ),
    )
    grid.add_row("services", _services_line(services))
    last_events = summary.get("last_events", []) or []
    event_table = _audit_table(last_events[-8:], title="Last events", compact=True)
    return Panel(
        Group(grid, Text(""), event_table),
        title="Security",
        title_align="left",
        border_style="aios.panel",
    )


# --- verdicts and chat -----------------------------------------------------


def render_provider(status: dict[str, Any]) -> Panel:
    """Provider configuration. Never includes the API key."""
    provider = str(status.get("provider") or "unknown").lower()
    external = bool(status.get("external"))
    ready = bool(status.get("ready"))
    grid = Table.grid(padding=(0, 2))
    grid.add_column(justify="right", style="aios.dim", no_wrap=True)
    grid.add_column(overflow="fold")
    grid.add_row("provider", _text(provider, max_length=32))
    grid.add_row("model", _text(status.get("model") or "-", max_length=64))
    grid.add_row(
        "access",
        Text(
            "external - prompts leave this machine"
            if external
            else "local only - nothing leaves this machine",
            style="yellow" if external else "green",
        ),
    )
    if provider == "groq":
        grid.add_row(
            "api key",
            Text(
                "configured",
                style="green",
            )
            if status.get("key_present")
            else Text("missing", style="bold red"),
        )
        grid.add_row(
            "external",
            Text(
                "allowed",
                style="green",
            )
            if status.get("external_allowed")
            else Text("disabled", style="bold red"),
        )
    grid.add_row(
        "config", Text("complete", style="green") if ready else Text("incomplete", style="bold red")
    )
    hint = status.get("hint")
    body: Any = grid
    if hint:
        body = Group(grid, Text(""), _text(hint, max_length=240, style="aios.warn"))
    return Panel(
        body,
        title="Model provider",
        title_align="left",
        border_style="aios.ok" if ready else "aios.warn",
    )


def render_verdict(verdict: dict[str, Any], *, target: str | None = None) -> Panel:
    decision = str(verdict.get("decision") or "UNKNOWN").upper()
    risk = str(verdict.get("risk") or "UNKNOWN").upper()
    state = verdict.get("state")
    policy = verdict.get("policy") or {}
    grid = Table.grid(padding=(0, 2))
    grid.add_column(justify="right", style="aios.dim")
    grid.add_column(overflow="fold")
    grid.add_row("action", _text(verdict.get("action"), max_length=120))
    if target:
        grid.add_row("target", _text(target, max_length=240))
    grid.add_row("risk", risk_badge(risk))
    grid.add_row("decision", decision_badge(decision))
    grid.add_row("state", _lifecycle(state, decision))
    denial = verdict.get("denial_reason")
    if denial:
        grid.add_row(
            "why",
            Text(denial_explanation(denial), style="bold red" if decision == "DENY" else ""),
        )
    reason = verdict.get("reason")
    if reason:
        grid.add_row("reason", _text(reason, max_length=180))
    source = policy.get("source") or verdict.get("source")
    if source:
        grid.add_row("policy", _text(source, max_length=48))
    policy_id = policy.get("policy_id")
    if policy_id:
        grid.add_row("policy id", _text(policy_id, max_length=48))
    duration = verdict.get("duration_ms")
    if duration is not None:
        grid.add_row("duration", Text(f"{_number(duration):.1f} ms"))
    if decision == "CONFIRM":
        grid.add_row(
            "next",
            Text("Approve before anything runs.", style="yellow"),
        )
    return Panel(
        grid,
        title=f"{decision} · {risk}",
        title_align="left",
        border_style=decision_style(decision),
    )


def render_confirmation(action: object, target: object, risk: object) -> Panel:
    body = Group(
        Text.assemble(
            ("action  ", "aios.dim"),
            _text(action, max_length=120),
        ),
        Text.assemble(
            ("target  ", "aios.dim"),
            _text(target, max_length=240),
        ),
        Text.assemble(("risk    ", "aios.dim"), risk_badge(risk)),
        Text(""),
        Text("Approve? [y/N]", style="bold"),
    )
    return Panel(
        body,
        title="CONFIRM",
        title_align="left",
        border_style=risk_style(risk),
    )


def _proposal_payload(request: Any) -> dict[str, Any]:
    if isinstance(request, dict):
        return request
    to_payload = getattr(request, "to_payload", None)
    if callable(to_payload):
        return to_payload()
    return {}


def render_proposal(request: Any, *, target: str | None = None) -> Panel:
    payload = _proposal_payload(request)
    grid = Table.grid(padding=(0, 2))
    grid.add_column(justify="right", style="aios.dim")
    grid.add_column(overflow="fold")
    grid.add_row("action", _text(payload.get("type"), max_length=120))
    if target:
        grid.add_row("target", _text(target, max_length=240))
    params = payload.get("params") or {}
    grid.add_row(
        "params",
        _block(json.dumps(params, indent=2, ensure_ascii=False), max_length=1200),
    )
    if payload.get("intent"):
        grid.add_row("intent", _text(payload.get("intent"), max_length=200))
    return Panel(
        grid,
        title="PROPOSED BY AI",
        title_align="left",
        border_style="aios.panel",
    )


def render_plan(plan: dict[str, Any]) -> Panel:
    """Show every exact step and the hash the operator is being asked to approve.

    The hash is the approval. Nothing here decides anything; it only makes the
    core-built plan reviewable before the explicit apply call.
    """
    grid = Table.grid(padding=(0, 2))
    grid.add_column(justify="right", style="aios.dim")
    grid.add_column(overflow="fold")
    action = plan.get("action") or plan.get("kind")
    grid.add_row("action", _text(action, max_length=120))
    target = plan.get("target")
    if target:
        grid.add_row("target", _text(target, max_length=240))
    steps = plan.get("steps")
    lines: list[str] = []
    if isinstance(steps, list):
        for index, step in enumerate(steps, start=1):
            if not isinstance(step, dict):
                continue
            lines.append(
                f"{index}. {step.get('step_id')}  {step.get('action')}  ->  {step.get('target')}"
            )
            params = step.get("params")
            if isinstance(params, dict) and params:
                lines.append(
                    "   " + json.dumps(params, sort_keys=True, ensure_ascii=False, default=str)
                )
    grid.add_row("steps", _block("\n".join(lines), max_length=4000))
    if plan.get("plan_id"):
        grid.add_row("plan id", _text(plan.get("plan_id"), max_length=80))
    grid.add_row("hash", _text(plan.get("plan_hash"), max_length=80, style="bold"))
    if plan.get("expires_at"):
        grid.add_row("expires", _text(plan.get("expires_at"), max_length=64))
    return Panel(
        grid,
        title="APPROVAL PLAN",
        title_align="left",
        border_style="red",
    )


def render_thinking(plan: dict[str, Any], *, verbose: bool = False) -> Panel:
    if not verbose:
        summary = Text.assemble(
            (sanitize_inline(plan.get("provider", "model"), max_length=32), "aios.title"),
            " · ",
            (sanitize_inline(plan.get("model", "-"), max_length=64), "aios.dim"),
            " · thinking (use --verbose to expand)",
            style="aios.dim",
        )
        return Panel(summary, title="Thinking / Plan", title_align="left", border_style="aios.dim")
    grid = Table.grid(padding=(0, 2))
    grid.add_column(justify="right", style="aios.dim")
    grid.add_column(overflow="fold")
    grid.add_row("provider", _text(plan.get("provider", "-")))
    grid.add_row("model", _text(plan.get("model", "-")))
    grid.add_row("external", Text("yes" if plan.get("external") else "no"))
    grid.add_row("prompt", _text(plan.get("prompt_hash", "-"), max_length=64))
    if plan.get("reason"):
        grid.add_row("reason", _text(plan.get("reason"), max_length=200))
    if plan.get("raw"):
        grid.add_row("raw", _block(plan.get("raw"), max_length=4000))
    return Panel(grid, title="Thinking / Plan", title_align="left", border_style="aios.panel")


def render_result(data: Any, *, source: object = None, trust_domain: object = None) -> Panel:
    header = Text()
    if source:
        header.append_text(Text.assemble(("source ", "aios.dim"), _text(source, max_length=64)))
        header.append("  ")
    if trust_domain:
        header.append_text(Text.assemble(("trust ", "aios.dim"), trust_badge(trust_domain)))
    try:
        encoded = json.dumps(data, indent=2, ensure_ascii=False, default=str)
    except (TypeError, ValueError):
        encoded = str(data)
    body = Group(header, Text(""), _block(encoded, max_length=8000))
    return Panel(body, title="Result", title_align="left", border_style="aios.panel")


def render_answer(text: object) -> Markdown:
    # Hyperlinks are disabled so model output cannot emit clickable links.
    return Markdown(sanitize_block(text, max_length=20_000), hyperlinks=False)


def render_error(message: object, *, next_step: object | None = None) -> Panel:
    body: Any = _block(message, max_length=2000, style="bold red")
    if next_step:
        body = Group(body, Text(""), _block(next_step, max_length=500, style="aios.dim"))
    return Panel(body, title="Error", title_align="left", border_style="red")


def render_history(turns: list[dict[str, Any]]) -> Table | Panel:
    if not turns:
        return Panel(
            Text("No turns in this session yet.", style="aios.dim"),
            title="History",
            title_align="left",
            border_style="aios.panel",
        )
    table = _table(title="History", caption=f"{len(turns)} turns")
    table.add_column("#", justify="right", no_wrap=True)
    table.add_column("QUESTION", overflow="fold")
    table.add_column("DECISION", no_wrap=True)
    table.add_column("ANSWER", overflow="fold")
    for index, turn in enumerate(turns, start=1):
        table.add_row(
            Text(str(index)),
            _text(turn.get("question"), max_length=120),
            decision_badge(turn.get("decision")),
            _text(turn.get("answer"), max_length=160),
        )
    return table


def render_session(
    *,
    session_id: object,
    model: object,
    health: object,
    trust: object,
    turns: int,
) -> Panel:
    grid = Table.grid(padding=(0, 2))
    grid.add_column(justify="right", style="aios.dim")
    grid.add_column(overflow="fold")
    grid.add_row("session", _text(session_id, max_length=48))
    grid.add_row("model", _text(model, max_length=64))
    grid.add_row("health", _text(health, max_length=120))
    grid.add_row("trust", _text(trust, max_length=64))
    grid.add_row("turns", Text(str(turns)))
    return Panel(grid, title="Session", title_align="left", border_style="aios.panel")


__all__ = [
    "denial_explanation",
    "render_actions",
    "render_answer",
    "render_audit",
    "render_confirmation",
    "render_cpu",
    "render_diagnose",
    "render_error",
    "render_history",
    "render_memory",
    "render_network",
    "render_plan",
    "render_processes",
    "render_proposal",
    "render_result",
    "render_security",
    "render_session",
    "render_status",
    "render_thinking",
    "render_verdict",
]
