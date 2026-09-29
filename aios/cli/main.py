"""AIOS command-line interface.

Two families of commands:

    aios status|cpu|memory|processes|network|hostname
        Direct read-only observation.

    aios validate|schema|actions
        Action Protocol tooling, no execution.

Execution (`aios actions run`, `aios ask`) is added in v0.4 when the security
engine and ledger exist, so that no command can currently reach the gateway
without passing through authorization.
"""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path
from typing import Annotated, Any

import typer
from rich.console import Console, Group
from rich.table import Table
from rich.text import Text

from aios.cli.watch import Sparkline, WatchConfig, WatchError, kv_table, run_watch
from aios.config import Settings, get_settings
from aios.gateway import ActionNotPermitted, OSGateway, PreconditionFailed
from aios.models import (
    FORBIDDEN_ACTION_NAMES,
    PARAMS_MAP,
    ActionRequest,
    ActionType,
)
from aios.observers.process import ProcessNotFound

app = typer.Typer(
    name="aios",
    help="AIOS — secure AI operating system control plane (read-only).",
    no_args_is_help=True,
    add_completion=False,
)
console = Console()
err_console = Console(stderr=True)


def _settings() -> Settings:
    return get_settings()


def _gateway() -> OSGateway:
    s = _settings()
    return OSGateway(
        proc_root=s.proc_root,
        sys_root=s.sys_root,
        max_read_bytes=s.max_read_bytes,
        max_dir_entries=s.max_dir_entries,
    )


def _dump(data: Any) -> None:
    console.print_json(json.dumps(data, default=str))


def _jsonable(obs: Any) -> dict[str, Any]:
    """Serialise an observation with its provenance envelope intact.

    Every --json path goes through here so the trust domain and source travel
    with the payload. A bare dump of ``obs.data`` would drop them, and the
    caller would have no way to tell kernel state from model output.
    """
    payload = obs.data.model_dump(mode="json") if hasattr(obs.data, "model_dump") else obs.data
    return {
        "type": obs.type,
        "source": obs.source,
        "origin": obs.origin.value,
        "trust_domain": obs.trust_domain.value,
        "trusted": obs.is_trusted,
        "timestamp": obs.timestamp.isoformat(),
        "data": payload,
    }


def _observe(
    action_type: ActionType,
    params: dict[str, Any] | None = None,
    action_id: str = "cli-observe",
) -> Any:
    """Run one whitelisted read action and return its observation."""
    request = ActionRequest(
        action_id=action_id,
        agent_id="local-agent",
        session_id="cli",
        type=action_type,
        params=params or {},
    )
    return _gateway().execute(request)


def _fail(exc: Exception) -> None:
    err_console.print(f"[bold red]error:[/] {exc}")
    raise typer.Exit(code=1)


@app.command()
def status(
    watch: Annotated[
        bool, typer.Option("-w", "--watch", help="Redraw continuously until ctrl-c")
    ] = False,
    interval: Annotated[float, typer.Option(help="Sampling interval (watch mode)")] = 1.0,
    count: Annotated[
        int | None, typer.Option("--count", help="Stop after N samples (watch mode)")
    ] = None,
    json_out: Annotated[bool, typer.Option("--json", help="Raw JSON output")] = False,
) -> None:
    """Machine identity, kernel, uptime, and resource summary.

    With `-w`, the identity block is redrawn each interval and the volatile
    figures — uptime, process count, temperatures, open files — visibly tick.
    """
    if watch:
        _watch_status(interval, count, json_out)
        return
    try:
        obs = _observe(ActionType.SYSTEM_STATUS)
    except (ActionNotPermitted, PreconditionFailed, OSError, ValueError) as exc:
        _fail(exc)
        return
    if json_out:
        _dump(_jsonable(obs))
        return

    d = obs.data
    table = Table(title=f"AIOS system status — {d.hostname}", show_header=False)
    table.add_column("field", style="cyan")
    table.add_column("value", style="white")
    table.add_row("hostname", d.hostname)
    table.add_row("kernel", f"{d.kernel} {d.kernel_version}".strip() or "-")
    table.add_row("architecture", d.architecture or "-")
    table.add_row("uptime", f"{d.uptime_s:.0f}s" if d.uptime_s is not None else "-")
    table.add_row("boot time (UTC)", d.boot_time_utc or "-")
    table.add_row("logical cores", str(d.logical_cores or "-"))
    table.add_row("processes (total)", str(d.processes_total or "-"))
    table.add_row("open files", str(d.open_files or "-"))
    table.add_row("block devices", ", ".join(d.block_devices) or "-")
    table.add_row("net devices", ", ".join(d.net_devices) or "-")
    if d.thermal_zones:
        for zone, temp in d.thermal_zones.items():
            table.add_row(f"thermal {zone}", f"{temp} C")
    if d.read_errors:
        table.add_row("read errors", ", ".join(d.read_errors))
    console.print(table)
    console.print(f"[dim]source: {obs.source} (trust {obs.trust_domain.value})[/]")


def _watch_status(interval: float, count: int | None, json_out: bool) -> None:
    try:
        cfg = WatchConfig.build(interval, count, json_out)
    except WatchError as exc:
        _fail(exc)
        return

    gateway = _gateway()
    proc_spark = Sparkline(width=40)
    temp_spark: dict[str, Sparkline] = {}
    first_uptime: float | None = None

    def fetch() -> Any:
        return gateway.execute(
            ActionRequest(
                action_id="cli-watch-status",
                agent_id="local-agent",
                session_id="cli",
                type=ActionType.SYSTEM_STATUS,
                params={},
            )
        )

    def render(obs: Any, tick: int) -> Any:
        nonlocal first_uptime
        d = obs.data
        if first_uptime is None and d.uptime_s is not None:
            first_uptime = d.uptime_s
        proc_spark.push(float(d.processes_total or 0))

        t = kv_table()
        t.add_row("sample", f"{tick}  (every {cfg.interval_s:.2f}s)")
        t.add_row("hostname", d.hostname)
        t.add_row("kernel", f"{d.kernel} {d.kernel_version}".strip() or "-")
        t.add_row("architecture", d.architecture or "-")
        if d.uptime_s is not None and first_uptime is not None:
            t.add_row("uptime", f"{d.uptime_s:.0f}s  (+{d.uptime_s - first_uptime:.0f}s this run)")
        else:
            t.add_row("uptime", "-")
        t.add_row("logical cores", str(d.logical_cores or "-"))
        procs = float(d.processes_total or 0)
        # Headroom above the current count, so the sparkline does not sit
        # pinned at full height the whole time.
        proc_window = max(10.0, procs * 1.1)
        proc_hist = proc_spark.render(lo=0.0, hi=proc_window)
        t.add_row("processes", f"{d.processes_total or '-'}  {proc_hist}")
        if d.threads_total is not None:
            t.add_row("threads", str(d.threads_total))
        t.add_row("open files", str(d.open_files or "-"))
        if d.block_devices:
            t.add_row("block devices", ", ".join(d.block_devices))
        if d.net_devices:
            t.add_row("net devices", ", ".join(d.net_devices))
        for zone, temp in d.thermal_zones.items():
            spark = temp_spark.setdefault(zone, Sparkline(width=30))
            spark.push(temp)
            t.add_row(f"thermal {zone}", f"{temp:.1f} C  {spark.render(lo=20.0, hi=100.0)}")
        if d.read_errors:
            t.add_row("read errors", ", ".join(d.read_errors))
        t.add_row("source", f"{obs.source} (trust {obs.trust_domain.value})")
        return t

    try:
        run_watch(console, cfg, fetch, render, header="[bold]AIOS status — live[/]")
    except (ActionNotPermitted, PreconditionFailed, OSError, ValueError) as exc:
        _fail(exc)


@app.command()
def cpu(
    interval: Annotated[float, typer.Option(help="Sampling interval in seconds")] = 0.25,
    watch: Annotated[
        bool,
        typer.Option("-w", "--watch", help="Redraw continuously until ctrl-c"),
    ] = False,
    count: Annotated[
        int | None, typer.Option("--count", help="Stop after N samples (watch mode)")
    ] = None,
    json_out: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """CPU utilisation, load average, per-core and frequency data.

    With `-w`, keeps sampling and redraws in place. The percentage figures are
    true per-interval deltas from /proc/stat, not a running average.
    """
    if watch:
        _watch_cpu(interval, count, json_out)
        return
    try:
        obs = _observe(ActionType.SYSTEM_CPU, {"interval_s": interval})
    except (ActionNotPermitted, PreconditionFailed, OSError, ValueError) as exc:
        _fail(exc)
        return
    if json_out:
        _dump(_jsonable(obs))
        return

    d = obs.data
    pct = d.percent or {}
    total = pct.get("total")
    bar = _bar(total) if total is not None else "[dim]needs two samples[/]"
    table = Table(show_header=False)
    table.add_column("field", style="cyan")
    table.add_column("value")
    table.add_row("logical cores", str(d.logical_cores))
    table.add_row("utilisation", f"{bar} {total if total is not None else '-'}%")
    if pct:
        table.add_row(
            "user / system / iowait",
            f"{pct.get('user')}% / {pct.get('system')}% / {pct.get('iowait')}%",
        )
        if pct.get("steal"):
            table.add_row("steal", f"{pct['steal']}%")
    table.add_row(
        "load (1/5/15m)",
        f"{d.load_average_1m} / {d.load_average_5m} / {d.load_average_15m}",
    )
    if d.per_core:
        cores = Table(title="per core")
        cores.add_column("core", style="cyan")
        cores.add_column("utilisation")
        for core in d.per_core:
            cores.add_row(core.name, _bar(core.percent) if core.percent is not None else "-")
        console.print(table)
        console.print(cores)
    else:
        console.print(table)

    if d.frequencies:
        freq = Table(title="cpufreq")
        freq.add_column("cpu", style="cyan")
        freq.add_column("current")
        freq.add_column("governor")
        for f in d.frequencies:
            freq.add_row(f.cpu, f.human, f.scaling_governor or "-")
        console.print(freq)


def _watch_cpu(interval: float, count: int | None, json_out: bool) -> None:
    """Live CPU view.

    One gateway for the whole run. ``CpuObserver`` keeps the previous
    /proc/stat sample in ``self._prev`` and computes percentages from the
    delta, so a fresh gateway per tick would have no baseline and could only
    ever report a zero-length window.
    """
    try:
        cfg = WatchConfig.build(interval, count, json_out)
    except WatchError as exc:
        _fail(exc)
        return

    # The interval is the loop's pacing; the observer's own sleep is only for
    # establishing its first baseline, so keep it small and let the loop wait.
    gateway = _gateway()
    spark = Sparkline()

    def fetch() -> Any:
        return gateway.execute(
            ActionRequest(
                action_id="cli-watch-cpu",
                agent_id="local-agent",
                session_id="cli",
                type=ActionType.SYSTEM_CPU,
                params={"interval_s": cfg.interval_s},
            )
        )

    def render(obs: Any, tick: int) -> Any:
        d = obs.data
        pct = d.percent or {}
        total = pct.get("total")
        spark.push(total)

        head = kv_table()
        head.add_row("sample", f"{tick}")
        head.add_row("interval", f"{cfg.interval_s:.2f}s")
        head.add_row("logical cores", str(d.logical_cores))
        head.add_row(
            "utilisation",
            f"{_bar(total)} {f'{total:.1f}%' if total is not None else '-'}",
        )
        head.add_row("history (60s)", spark.render())
        if pct:
            head.add_row(
                "user/sys/iowait",
                f"{pct.get('user', 0):.1f}% / {pct.get('system', 0):.1f}% "
                f"/ {pct.get('iowait', 0):.1f}%",
            )
        head.add_row(
            "load 1/5/15m",
            f"{d.load_average_1m} / {d.load_average_5m} / {d.load_average_15m}",
        )

        cores = Table(title="per core")
        cores.add_column("core", style="cyan", no_wrap=True)
        cores.add_column("utilisation")
        cores.add_column("", overflow="ignore")
        for core in d.per_core:
            pct_val = core.percent
            cores.add_row(
                core.name,
                _bar(pct_val) if pct_val is not None else "-",
                f"{pct_val:.1f}%" if pct_val is not None else "-",
            )

        parts: list[Any] = [head, cores]
        if d.frequencies:
            freq = Table(title="cpufreq")
            freq.add_column("cpu", style="cyan", no_wrap=True)
            freq.add_column("current")
            freq.add_column("governor")
            for f in d.frequencies:
                freq.add_row(f.cpu, f.human, f.scaling_governor or "-")
            parts.append(freq)
        parts.append(Text(f"source: {obs.source} (trust {obs.trust_domain.value})", style="dim"))
        return Group(*parts)

    try:
        run_watch(console, cfg, fetch, render, header="[bold]AIOS cpu — live[/]")
    except (ActionNotPermitted, PreconditionFailed, OSError, ValueError) as exc:
        _fail(exc)


def _bar(percent: float, width: int = 24) -> str:
    filled = int(round(percent / 100 * width))
    colour = "green" if percent < 50 else "yellow" if percent < 85 else "red"
    return f"[{colour}]{'█' * filled}{'░' * (width - filled)}[/]"


@app.command()
def memory(
    watch: Annotated[
        bool, typer.Option("-w", "--watch", help="Redraw continuously until ctrl-c")
    ] = False,
    interval: Annotated[float, typer.Option(help="Sampling interval (watch mode)")] = 1.0,
    count: Annotated[
        int | None, typer.Option("--count", help="Stop after N samples (watch mode)")
    ] = None,
    json_out: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Memory and swap utilisation.

    With `-w`, keeps sampling. Memory moves on a scale of seconds rather than
    milliseconds, so the default watch interval here is slower than for CPU.
    """
    if watch:
        _watch_memory(interval, count, json_out)
        return
    try:
        obs = _observe(ActionType.SYSTEM_MEMORY, {"include_fields": True})
    except (ActionNotPermitted, PreconditionFailed, OSError, ValueError) as exc:
        _fail(exc)
        return
    if json_out:
        _dump(_jsonable(obs))
        return

    d = obs.data
    total_gb = d.total_kb / 1024 / 1024
    used_gb = d.used_kb / 1024 / 1024
    avail_gb = d.available_kb / 1024 / 1024
    table = Table(show_header=False)
    table.add_column("field", style="cyan")
    table.add_column("value")
    table.add_row("total", f"{total_gb:.2f} GiB")
    table.add_row("used", f"{used_gb:.2f} GiB  {_bar(d.used_percent)} {d.used_percent}%")
    table.add_row("available", f"{avail_gb:.2f} GiB  {d.available_percent}%")
    table.add_row("buffers / cached", f"{d.buffers_kb / 1024:.0f} / {d.cached_kb / 1024:.0f} MiB")
    table.add_row(
        "swap",
        f"{d.swap_used_kb / 1024:.0f} / {d.swap_total_kb / 1024:.0f} MiB "
        f"({d.swap_used_percent}%)",
    )
    if d.hugepages_total:
        table.add_row(
            "hugepages",
            f"{d.hugepages_total - (d.hugepages_free or 0)}/{d.hugepages_total} used",
        )
    console.print(table)
    console.print(f"[dim]source: {obs.source} (trust {obs.trust_domain.value})[/]")


def _watch_memory(interval: float, count: int | None, json_out: bool) -> None:
    try:
        cfg = WatchConfig.build(interval, count, json_out)
    except WatchError as exc:
        _fail(exc)
        return

    gateway = _gateway()
    used_spark = Sparkline()
    avail_spark = Sparkline()

    def fetch() -> Any:
        return gateway.execute(
            ActionRequest(
                action_id="cli-watch-memory",
                agent_id="local-agent",
                session_id="cli",
                type=ActionType.SYSTEM_MEMORY,
                params={"include_fields": True},
            )
        )

    def render(obs: Any, tick: int) -> Any:
        d = obs.data
        used_spark.push(d.used_percent)
        avail_spark.push(d.available_percent)
        t = kv_table()
        t.add_row("sample", f"{tick}  (every {cfg.interval_s:.2f}s)")
        t.add_row("total", f"{d.total_kb / 1024 / 1024:.2f} GiB")
        t.add_row(
            "used",
            f"{_bar(d.used_percent)} {d.used_percent:.1f}%  "
            f"({d.used_kb / 1024 / 1024:.2f} GiB)",
        )
        t.add_row("used history", used_spark.render())
        t.add_row(
            "available",
            f"{_bar(d.available_percent)} {d.available_percent:.1f}%  "
            f"({d.available_kb / 1024 / 1024:.2f} GiB)",
        )
        t.add_row("avail history", avail_spark.render())
        t.add_row(
            "buffers / cached",
            f"{d.buffers_kb / 1024:.0f} / {d.cached_kb / 1024:.0f} MiB",
        )
        if d.swap_total_kb:
            t.add_row(
                "swap",
                f"{_bar(d.swap_used_percent)} {d.swap_used_percent:.1f}%  "
                f"({d.swap_used_kb / 1024:.0f} / {d.swap_total_kb / 1024:.0f} MiB)",
            )
        if d.hugepages_total:
            t.add_row(
                "hugepages",
                f"{d.hugepages_total - (d.hugepages_free or 0)}/{d.hugepages_total} used",
            )
        t.add_row("source", f"{obs.source} (trust {obs.trust_domain.value})")
        return t

    try:
        run_watch(console, cfg, fetch, render, header="[bold]AIOS memory — live[/]")
    except (ActionNotPermitted, PreconditionFailed, OSError, ValueError) as exc:
        _fail(exc)


@app.command()
def hostname(json_out: Annotated[bool, typer.Option("--json")] = False) -> None:
    """Hostname and OS name."""
    try:
        obs = _observe(ActionType.SYSTEM_HOSTNAME)
    except (ActionNotPermitted, PreconditionFailed, OSError, ValueError) as exc:
        _fail(exc)
        return
    if json_out:
        _dump(_jsonable(obs))
        return
    console.print(f"{obs.data['hostname']}  [dim]{obs.data.get('os_name') or ''}[/]")


@app.command()
def processes(
    limit: Annotated[int, typer.Option(help="Maximum rows")] = 20,
    sort: Annotated[str, typer.Option(help="cpu|memory|pid|name")] = "cpu",
    name: Annotated[str | None, typer.Option("--name", help="Substring filter")] = None,
    show_cmdline: Annotated[bool, typer.Option("--cmdline")] = False,
    watch: Annotated[
        bool, typer.Option("-w", "--watch", help="Redraw continuously until ctrl-c")
    ] = False,
    interval: Annotated[float, typer.Option(help="Sampling interval (watch mode)")] = 1.0,
    count: Annotated[
        int | None, typer.Option("--count", help="Stop after N samples (watch mode)")
    ] = None,
    json_out: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """List processes.

    With `-w`, re-reads the process table on an interval and redraws in place.
    Per-process cpu% is a real delta against the previous sample, so the first
    frame shows "-" and the second onward shows real usage.
    """
    if watch:
        _watch_processes(limit, sort, name, show_cmdline, interval, count, json_out)
        return
    params: dict[str, Any] = {"limit": limit, "sort_by": sort, "include_cmdline": show_cmdline}
    if name:
        params["name_filter"] = name
    try:
        obs = _observe(ActionType.PROCESS_LIST, params)
    except (ActionNotPermitted, PreconditionFailed, OSError, ValueError) as exc:
        _fail(exc)
        return
    if json_out:
        _dump(_jsonable(obs))
        return

    d = obs.data
    table = Table(
        title=f"processes (showing {d.returned} of {d.total_found}, sorted by {sort})"
    )
    table.add_column("pid", style="cyan", justify="right")
    table.add_column("name")
    table.add_column("state")
    table.add_column("user", justify="right")
    table.add_column("rss", justify="right")
    table.add_column("cpu%", justify="right")
    if show_cmdline:
        table.add_column("cmdline", style="dim", overflow="fold")
    for p in d.processes:
        # Process names and cmdlines are attacker-controlled strings. They are
        # rendered as data, and rich markup in them is escaped, so a process
        # called "[red]pwned[/]" cannot spoof the CLI's own output.
        table.add_row(
            str(p.pid),
            Text(p.name),
            p.state_description,
            str(p.uid if p.uid is not None else "-"),
            _human_bytes(p.rss_bytes),
            f"{p.cpu_percent:.1f}" if p.cpu_percent is not None else "-",
            Text(" ".join(p.cmdline)[:120]) if show_cmdline else "",
        )
    console.print(table)
    if d.skipped:
        console.print(f"[dim]{len(d.skipped)} process(es) unreadable, skipped[/]")
    if not d.cpu_percent_available:
        console.print("[dim]cpu% needs a second sample; run again for values[/]")


def _watch_processes(
    limit: int,
    sort: str,
    name: str | None,
    show_cmdline: bool,
    interval: float,
    count: int | None,
    json_out: bool,
) -> None:
    try:
        cfg = WatchConfig.build(interval, count, json_out)
    except WatchError as exc:
        _fail(exc)
        return

    params: dict[str, Any] = {"limit": limit, "sort_by": sort, "include_cmdline": show_cmdline}
    if name:
        params["name_filter"] = name

    gateway = _gateway()
    # One observer for the run: per-process cpu% comes from the previous
    # /proc/[pid]/stat sample held on the observer, so a per-tick gateway
    # would reset it every frame.
    top_cpu = Sparkline(width=20)

    def fetch() -> Any:
        return gateway.execute(
            ActionRequest(
                action_id="cli-watch-processes",
                agent_id="local-agent",
                session_id="cli",
                type=ActionType.PROCESS_LIST,
                params=params,
            )
        )

    def render(obs: Any, tick: int) -> Any:
        d = obs.data
        if d.processes:
            top_cpu.push(d.processes[0].cpu_percent or 0.0)
        table = Table(
            title=f"processes — sample {tick}, {d.returned} of {d.total_found}, "
            f"every {cfg.interval_s:.2f}s, sorted by {sort}"
        )
        table.add_column("pid", style="cyan", justify="right")
        table.add_column("name")
        table.add_column("state")
        table.add_column("rss", justify="right")
        table.add_column("cpu%", justify="right")
        table.add_column("bar")
        if show_cmdline:
            table.add_column("cmdline", style="dim", overflow="fold")
        for p in d.processes:
            # Names and cmdlines are attacker-controlled. They are wrapped in
            # Text so rich markup in them is escaped and cannot spoof the
            # monitor's own output — more important while live, since a table
            # that redraws is being read at a glance.
            pct = p.cpu_percent
            table.add_row(
                str(p.pid),
                Text(p.name),
                p.state_description,
                _human_bytes(p.rss_bytes),
                f"{pct:.1f}" if pct is not None else "-",
                _bar(min(pct, 100.0), width=12) if pct is not None else "-",
                Text(" ".join(p.cmdline)[:100]) if show_cmdline else "",
            )
        parts: list[Any] = [table]
        # A process can exceed 100% of one core, so the window follows the
        # peak seen so far rather than clipping every busy process to full.
        peak = top_cpu.peak or 100.0
        parts.append(
            Text(
                f"top-process cpu history  {top_cpu.render(lo=0.0, hi=max(100.0, peak))}",
                style="dim",
            )
        )
        if d.skipped:
            parts.append(Text(f"{len(d.skipped)} unreadable, skipped", style="yellow"))
        if not d.cpu_percent_available:
            parts.append(Text("cpu% needs a second sample", style="dim"))
        return Group(*parts)

    try:
        run_watch(console, cfg, fetch, render, header="[bold]AIOS processes — live[/]")
    except (ActionNotPermitted, PreconditionFailed, OSError, ValueError) as exc:
        _fail(exc)


def _human_bytes(value: int | None) -> str:
    if value is None:
        return "-"
    size = float(value)
    for unit in ("B", "KiB", "MiB", "GiB"):
        if size < 1024 or unit == "GiB":
            return f"{size:.0f} {unit}" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} GiB"


@app.command("inspect")
def inspect(
    pid: Annotated[int, typer.Argument(help="Process id")],
    watch: Annotated[
        bool, typer.Option("-w", "--watch", help="Redraw continuously until ctrl-c")
    ] = False,
    interval: Annotated[float, typer.Option(help="Sampling interval (watch mode)")] = 1.0,
    count: Annotated[
        int | None, typer.Option("--count", help="Stop after N samples (watch mode)")
    ] = None,
    json_out: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Detailed view of one process, including limits and I/O counters.

    With `-w`, follows a single process: RSS, state, and I/O counters update
    each interval, and the watch stops on its own when the process exits.
    """
    if watch:
        _watch_inspect(pid, interval, count, json_out)
        return
    try:
        obs = _observe(ActionType.PROCESS_INSPECT, {"pid": pid})
    except (ProcessNotFound, PreconditionFailed) as exc:
        _fail(exc)
        return
    except (ActionNotPermitted, OSError, ValueError) as exc:
        _fail(exc)
        return
    if json_out:
        _dump(_jsonable(obs))
        return

    d = obs.data
    table = Table(title=f"pid {d.pid} — {d.name}", show_header=False)
    table.add_column("field", style="cyan")
    table.add_column("value")
    table.add_row("name", Text(d.name))
    table.add_row("state", d.state_description)
    table.add_row("parent", str(d.ppid))
    table.add_row("uid / gid", f"{d.uid} / {d.gid}")
    table.add_row("threads", str(d.threads or "-"))
    table.add_row("rss", _human_bytes(d.rss_bytes))
    table.add_row("virtual", _human_bytes(d.vsize_bytes))
    table.add_row("uptime", f"{d.elapsed_s:.0f}s" if d.elapsed_s else "-")
    table.add_row("executable", d.executable or "-")
    table.add_row("cwd", d.cwd or "-")
    table.add_row("cgroup", d.cgroup or "-")
    if d.io:
        table.add_row("io read/write", f"{d.io.get('rchar', 0)} / {d.io.get('wchar', 0)}")
    if d.limits:
        table.add_row("limits", ", ".join(f"{k}={v}" for k, v in list(d.limits.items())[:4]))
    console.print(table)
    if d.cmdline:
        console.print("[bold]cmdline[/] (untrusted data):")
        console.print(Text(" ".join(d.cmdline), style="dim"))


def _watch_inspect(pid: int, interval: float, count: int | None, json_out: bool) -> None:
    try:
        cfg = WatchConfig.build(interval, count, json_out)
    except WatchError as exc:
        _fail(exc)
        return

    gateway = _gateway()
    rss_spark = Sparkline(width=30)

    def fetch() -> Any:
        return gateway.execute(
            ActionRequest(
                action_id="cli-watch-inspect",
                agent_id="local-agent",
                session_id="cli",
                type=ActionType.PROCESS_INSPECT,
                params={"pid": pid},
            )
        )

    tick = 0
    while True:
        tick += 1
        try:
            obs = fetch()
        except ProcessNotFound:
            # A watch on a process is a watch on a lifetime. Following one to
            # its end is the point, so exiting here is correct rather than an
            # error condition.
            console.print(Text(f"pid {pid} exited after {tick - 1} samples", style="yellow"))
            return
        except (ActionNotPermitted, PreconditionFailed, OSError, ValueError) as exc:
            _fail(exc)
            return

        d = obs.data
        rss_spark.push(float(d.rss_bytes or 0) / (1024 * 1024))
        console.print(_inspect_frame(d, tick, cfg, rss_spark, live=False))
        if cfg.count is not None and tick >= cfg.count:
            return
        time.sleep(cfg.interval_s)


def _inspect_frame(d: Any, tick: int, cfg: WatchConfig, rss_spark: Sparkline, live: bool) -> Any:
    table = kv_table(f"pid {d.pid} — sample {tick} (every {cfg.interval_s:.2f}s)")
    table.add_row("name", Text(d.name))
    table.add_row("state", d.state_description)
    table.add_row("parent", str(d.ppid))
    table.add_row("uid / gid", f"{d.uid} / {d.gid}")
    table.add_row("threads", str(d.threads or "-"))
    peak = rss_spark.peak or 1.0
    table.add_row(
        "rss",
        f"{_human_bytes(d.rss_bytes)}  {rss_spark.render(lo=0.0, hi=max(1.0, peak * 1.1))} MiB",
    )
    table.add_row("virtual", _human_bytes(d.vsize_bytes))
    table.add_row("uptime", f"{d.elapsed_s:.0f}s" if d.elapsed_s else "-")
    table.add_row("executable", d.executable or "-")
    table.add_row("cwd", d.cwd or "-")
    table.add_row("cgroup", d.cgroup or "-")
    if d.io:
        table.add_row("io read", f"{int(d.io.get('rchar', 0)):,} bytes")
        table.add_row("io write", f"{int(d.io.get('wchar', 0)):,} bytes")
    if d.limits:
        table.add_row(
            "limits",
            ", ".join(f"{k}={v}" for k, v in list(d.limits.items())[:4]),
        )
    if d.cmdline:
        # Untrusted, and rendered as data so markup inside cannot spoof the
        # frame around it.
        table.add_row("cmdline (untrusted)", Text(" ".join(d.cmdline)[:200], style="dim"))
    return table


@app.command()
def network(
    limit: Annotated[int, typer.Option(help="Maximum rows")] = 30,
    listening: Annotated[bool, typer.Option("--listening", help="Only listeners")] = False,
    unix_sockets: Annotated[bool, typer.Option("--unix", help="Include unix sockets")] = False,
    watch: Annotated[
        bool, typer.Option("-w", "--watch", help="Redraw continuously until ctrl-c")
    ] = False,
    interval: Annotated[float, typer.Option(help="Sampling interval (watch mode)")] = 1.0,
    count: Annotated[
        int | None, typer.Option("--count", help="Stop after N samples (watch mode)")
    ] = None,
    json_out: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Active and listening network connections from /proc/net.

    With `-w`, the connection table is re-read each interval, so short-lived
    connections and state changes show up as they happen.
    """
    if watch:
        _watch_network(limit, listening, unix_sockets, interval, count, json_out)
        return
    params: dict[str, Any] = {
        "limit": limit,
        "listening_only": listening,
        "include_unix": unix_sockets,
    }
    try:
        obs = _observe(ActionType.NETWORK_CONNECTIONS, params)
    except (ActionNotPermitted, PreconditionFailed, OSError, ValueError) as exc:
        _fail(exc)
        return
    if json_out:
        _dump(_jsonable(obs))
        return

    d = obs.data
    table = Table(title=f"connections ({d.summary.total} total)")
    table.add_column("proto", style="cyan")
    table.add_column("local")
    table.add_column("remote")
    table.add_column("state")
    table.add_column("process", style="dim")
    for c in d.connections:
        local = (
            f"{c.local_address}:{c.local_port}"
            if c.local_port
            else str(c.local_address)[:48]
        )
        remote = (
            f"{c.remote_address}:{c.remote_port}" if c.remote_address else "-"
        )
        table.add_row(
            c.family,
            Text(local),
            Text(remote),
            c.state or "-",
            Text(
                ", ".join(c.process_names)
                or ("pid:" + ",".join(map(str, c.pids)) if c.pids else "-")
            ),
        )
    console.print(table)
    states = ", ".join(f"{k}={v}" for k, v in sorted(d.summary.by_state.items()))
    console.print(f"[dim]{states} | attributed to a pid: {d.summary.attributed}[/]")
    if d.skipped_files:
        console.print(f"[yellow]unavailable: {', '.join(d.skipped_files)}[/]")


def _watch_network(
    limit: int,
    listening: bool,
    unix_sockets: bool,
    interval: float,
    count: int | None,
    json_out: bool,
) -> None:
    try:
        cfg = WatchConfig.build(interval, count, json_out)
    except WatchError as exc:
        _fail(exc)
        return

    params: dict[str, Any] = {
        "limit": limit,
        "listening_only": listening,
        "include_unix": unix_sockets,
    }
    gateway = _gateway()
    # Connection counts are far noisier than memory or CPU, so a short window
    # is enough to show churn without the sparkline becoming unreadable.
    conn_spark = Sparkline(width=60)
    previous: dict[tuple[str, str, str], str] = {}

    def fetch() -> Any:
        return gateway.execute(
            ActionRequest(
                action_id="cli-watch-network",
                agent_id="local-agent",
                session_id="cli",
                type=ActionType.NETWORK_CONNECTIONS,
                params=params,
            )
        )

    def render(obs: Any, tick: int) -> Any:
        d = obs.data
        conn_spark.push(float(d.summary.total))
        table = Table(
            title=f"connections — sample {tick}, {d.summary.total} total, "
            f"every {cfg.interval_s:.2f}s"
        )
        table.add_column("proto", style="cyan", no_wrap=True)
        table.add_column("local")
        table.add_column("remote")
        table.add_column("state")
        table.add_column("change", style="dim", no_wrap=True)
        table.add_column("process", style="dim")

        current: dict[tuple[str, str, str], str] = {}
        for c in d.connections:
            local = (
                f"{c.local_address}:{c.local_port}"
                if c.local_port
                else str(c.local_address)[:44]
            )
            remote = f"{c.remote_address}:{c.remote_port}" if c.remote_address else "-"
            key = (c.family, local, remote)
            state = c.state or "-"
            current[key] = state
            if tick == 1:
                change = Text("")
            elif key not in previous:
                change = Text("new", style="green")
            elif previous[key] != state:
                change = Text(f"{previous[key]} -> {state}", style="yellow")
            else:
                change = Text("")
            table.add_row(
                c.family,
                Text(local),
                Text(remote),
                state,
                change,
                Text(
                    ", ".join(c.process_names)
                    or ("pid:" + ",".join(map(str, c.pids)) if c.pids else "-")
                ),
            )
        if tick > 1:
            gone = [k for k in previous if k not in current]
            for key in gone[: limit // 2 or 5]:
                # Text is used deliberately: it renders as data, so a socket
                # whose address happens to contain markup cannot inject
                # styling into the monitor. Style is set on the Text itself
                # rather than in a string, because Text does not parse markup.
                table.add_row(
                    key[0],
                    Text(key[1], style="dim strike"),
                    Text(key[2], style="dim strike"),
                    Text("-", style="dim"),
                    Text("closed", style="red"),
                    Text("-", style="dim"),
                )
        previous.clear()
        previous.update(current)

        parts: list[Any] = [table]
        # Scale to the peak seen so a quiet host does not render every sample
        # as an identical full-height block.
        parts.append(
            Text(
                f"total history  {conn_spark.render(lo=0.0, hi=max(10.0, d.summary.total))}",
                style="dim",
            )
        )
        parts.append(
            Text(
                "states: "
                + ", ".join(f"{k}={v}" for k, v in sorted(d.summary.by_state.items())),
                style="dim",
            )
        )
        transports = ", ".join(f"{k}={v}" for k, v in sorted(d.summary.by_transport.items()))
        parts.append(
            Text(
                f"transports: {transports} | attributed: {d.summary.attributed}",
                style="dim",
            )
        )
        if d.skipped_files:
            parts.append(Text(f"unavailable: {', '.join(d.skipped_files)}", style="yellow"))
        return Group(*parts)

    try:
        run_watch(console, cfg, fetch, render, header="[bold]AIOS network — live[/]")
    except (ActionNotPermitted, PreconditionFailed, OSError, ValueError) as exc:
        _fail(exc)


@app.command()
def mounts(
    watch: Annotated[
        bool, typer.Option("-w", "--watch", help="Redraw continuously until ctrl-c")
    ] = False,
    interval: Annotated[float, typer.Option(help="Sampling interval (watch mode)")] = 2.0,
    count: Annotated[
        int | None, typer.Option("--count", help="Stop after N samples (watch mode)")
    ] = None,
    json_out: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Mounted real filesystems with usage.

    With `-w`, usage is re-read each interval so a filling disk is visible as
    it fills. Each bar is scaled against the filesystem's own capacity, so a
    16 GiB tmpfs and a 4 TiB volume are both readable.
    """
    if watch:
        _watch_mounts(interval, count, json_out)
        return
    try:
        obs = _observe(ActionType.FILESYSTEM_LIST, {"include_pseudo": False})
    except (ActionNotPermitted, PreconditionFailed, OSError, ValueError) as exc:
        _fail(exc)
        return
    if json_out:
        _dump(_jsonable(obs))
        return
    table = Table(title="filesystems")
    table.add_column("mount", style="cyan")
    table.add_column("type")
    table.add_column("used", justify="right")
    table.add_column("free", justify="right")
    table.add_column("usage")
    for m in obs.data.mounts:
        pct = m.used_percent
        table.add_row(
            m.mount_point,
            m.fs_type,
            _human_bytes(m.used_bytes),
            _human_bytes(m.free_bytes),
            f"{_bar(pct)} {pct}%" if pct is not None else "-",
        )
    console.print(table)


def _watch_mounts(interval: float, count: int | None, json_out: bool) -> None:
    try:
        cfg = WatchConfig.build(interval, count, json_out)
    except WatchError as exc:
        _fail(exc)
        return

    gateway = _gateway()
    sparks: dict[str, Sparkline] = {}

    def fetch() -> Any:
        return gateway.execute(
            ActionRequest(
                action_id="cli-watch-mounts",
                agent_id="local-agent",
                session_id="cli",
                type=ActionType.FILESYSTEM_LIST,
                params={"include_pseudo": False},
            )
        )

    def render(obs: Any, tick: int) -> Any:
        d = obs.data
        table = Table(
            title=f"filesystems — sample {tick}, every {cfg.interval_s:.2f}s, "
            f"ctrl-c to stop"
        )
        table.add_column("mount", style="cyan", no_wrap=True)
        table.add_column("type", no_wrap=True)
        table.add_column("used", justify="right")
        table.add_column("free", justify="right")
        table.add_column("usage")
        table.add_column("history")
        for m in d.mounts:
            pct = m.used_percent
            spark = sparks.setdefault(m.mount_point, Sparkline(width=30))
            spark.push(pct)
            table.add_row(
                m.mount_point,
                m.fs_type,
                _human_bytes(m.used_bytes),
                _human_bytes(m.free_bytes),
                f"{_bar(pct)} {pct}%" if pct is not None else "-",
                spark.render() if pct is not None else "-",
            )
        return table

    try:
        run_watch(console, cfg, fetch, render, header="[bold]AIOS mounts — live[/]")
    except (ActionNotPermitted, PreconditionFailed, OSError, ValueError) as exc:
        _fail(exc)


@app.command()
def ls(
    path: Annotated[str, typer.Argument(help="Directory to list")],
    all: Annotated[bool, typer.Option("--all", help="Include dotfiles")] = False,
    json_out: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """List directory metadata (names, sizes, modes — never contents)."""
    params: dict[str, Any] = {"path": path, "show_hidden": all}
    try:
        obs = _observe(ActionType.FILESYSTEM_LIST, params)
    except (ActionNotPermitted, PreconditionFailed, OSError, ValueError) as exc:
        _fail(exc)
        return
    if json_out:
        _dump(_jsonable(obs))
        return
    table = Table(title=path)
    table.add_column("name", style="cyan")
    table.add_column("mode")
    table.add_column("size", justify="right")
    table.add_column("owner", justify="right")
    for entry in obs.data.entries:
        table.add_row(
            Text(Path(entry.path).name + ("/" if entry.is_dir else "")),
            entry.mode or "-",
            _human_bytes(entry.size_bytes) if entry.is_file else "-",
            str(entry.owner_uid or "-"),
        )
    console.print(table)


@app.command()
def schema(
    json_out: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Print the Action Protocol schema the AI must produce."""
    payload = {
        "allowed_actions": sorted(PARAMS_MAP),
        "forbidden_actions": sorted(FORBIDDEN_ACTION_NAMES),
        "params": {name: model.model_json_schema() for name, model in sorted(PARAMS_MAP.items())},
    }
    if json_out:
        _dump(payload)
        return
    table = Table(title="AIOS action protocol")
    table.add_column("action", style="cyan")
    table.add_column("params")
    for name in sorted(PARAMS_MAP):
        fields = ", ".join(
            sorted(PARAMS_MAP[name].model_fields) or ["(none)"]
        )
        table.add_row(name, fields)
    console.print(table)
    console.print(
        f"[bold red]forbidden (no implementation, permanently denied in this build):[/] "
        f"{', '.join(sorted(FORBIDDEN_ACTION_NAMES)[:8])}, ..."
    )


@app.command()
def validate(
    file: Annotated[
        Path | None,
        typer.Argument(help="JSON file with an action proposal; omit to read stdin"),
    ] = None,
) -> None:
    """Validate an AI action proposal. Never executes it."""
    from aios.models import ActionRequest

    try:
        raw = file.read_text(encoding="utf-8") if file else sys.stdin.read()
    except OSError as exc:
        _fail(exc)
        return
    if not raw.strip():
        err_console.print("[bold red]error:[/] no input")
        raise typer.Exit(code=1)
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        err_console.print(f"[bold red]error:[/] invalid JSON: {exc}")
        raise typer.Exit(code=1) from exc
    if not isinstance(payload, dict):
        err_console.print("[bold red]error:[/] action must be a JSON object")
        raise typer.Exit(code=1)

    raw_type = payload.get("type")
    if isinstance(raw_type, str) and raw_type in FORBIDDEN_ACTION_NAMES:
        err_console.print(f"[bold red]DENIED[/] {raw_type} is a forbidden action type")
        raise typer.Exit(code=1)
    if isinstance(raw_type, str) and raw_type not in PARAMS_MAP:
        err_console.print(f"[bold red]DENIED[/] unknown action type: {raw_type!r}")
        raise typer.Exit(code=1)
    try:
        request = ActionRequest.model_validate(payload)
    except Exception as exc:
        err_console.print(f"[bold red]DENIED[/] {exc}")
        raise typer.Exit(code=1) from exc

    console.print(f"[green]VALID[/] {request.action_name}")
    console.print(f"  action_id:  {request.action_id}")
    console.print(f"  agent_id:   {request.agent_id}")
    console.print(f"  session_id: {request.session_id}")
    console.print(f"  trust:      {request.trust_domain.value} (origin {request.origin.value})")
    console.print("[bold]validated params[/]")
    _dump(request.typed_params.model_dump())
    console.print(
        "[dim]Validation only. Execution requires a capability check and a policy decision.[/]"
    )


@app.command()
def act(
    file: Annotated[
        Path | None,
        typer.Argument(help="JSON file with an action proposal; omit to read stdin"),
    ] = None,
    dry_run: Annotated[bool, typer.Option("--dry-run", help="Authorize without executing")] = False,
    json_out: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Submit an action proposal through the Security Engine.

    This is the CLI's *agent* path. The read-only commands above call the
    gateway directly because the operator is the caller; anything shaped like
    an AI proposal comes through here instead, so it is capability-checked,
    policy-checked, and written to the ledger. There is deliberately no other
    way to reach execution from the command line.
    """
    from aios.runtime import security_engine
    from aios.security import Decision, make_ai_request

    raw_type = None
    try:
        raw = file.read_text(encoding="utf-8") if file else sys.stdin.read()
        payload = json.loads(raw) if raw.strip() else None
    except (OSError, json.JSONDecodeError) as exc:
        _fail(exc)
        return
    if not isinstance(payload, dict):
        err_console.print("[bold red]error:[/] no action proposal provided")
        raise typer.Exit(code=1)

    raw_type = payload.get("type")
    if isinstance(raw_type, str) and raw_type in FORBIDDEN_ACTION_NAMES:
        err_console.print(f"[bold red]DENIED[/] {raw_type} is a forbidden action type")
        raise typer.Exit(code=1)

    try:
        request = make_ai_request(
            str(raw_type),
            payload.get("params") or {},
            agent_id=str(payload.get("agent_id") or "local-agent"),
            session_id=str(payload.get("session_id") or "cli"),
            requested_scope=payload.get("requested_scope") or {},
            intent=payload.get("intent"),
        )
    except Exception as exc:
        err_console.print(f"[bold red]DENIED[/] {exc}")
        raise typer.Exit(code=1) from exc

    with security_engine(_settings(), _gateway()) as engine:
        verdict = engine.authorize(request) if dry_run else engine.process(request)

    if json_out:
        _dump(
            {
                "action_id": verdict.action_id,
                "action": verdict.action,
                "state": verdict.state.value,
                "decision": verdict.decision.value,
                "risk": verdict.risk.value,
                "reason": verdict.reason,
                "denial_reason": verdict.denial_reason.value if verdict.denial_reason else None,
                "capability": verdict.capability.matched_capability if verdict.capability else None,
                "executed": verdict.observation is not None,
                "duration_ms": verdict.duration_ms,
            }
        )
    elif verdict.decision is Decision.ALLOW:
        colour = "green" if verdict.observation else "yellow"
        console.print(f"[bold {colour}]{verdict.decision.value}[/] {verdict.action}")
        console.print(f"  state:     {verdict.state.value}")
        console.print(f"  risk:      {verdict.risk.value}")
        matched = verdict.capability.matched_capability if verdict.capability else "-"
        console.print(f"  capability: {matched}")
        if verdict.observation:
            console.print(f"  source:    {verdict.observation.source}")
            _dump(verdict.observation.data)
        else:
            console.print("  [dim]authorized, not executed (--dry-run)[/]")
    else:
        reason = verdict.denial_reason.value if verdict.denial_reason else "-"
        err_console.print(
            f"[bold red]{verdict.decision.value}[/] {verdict.action} "
            f"({reason}) {verdict.reason}"
        )

    if verdict.decision is Decision.DENY:
        raise typer.Exit(code=1)


db_app = typer.Typer(help="Audit ledger and database schema.", no_args_is_help=True)
app.add_typer(db_app, name="db")


@db_app.command("init")
def db_init() -> None:
    """Create the audit schema. Idempotent."""
    from aios.db.session import init_db

    result = init_db()
    if not result.get("ok"):
        err_console.print(f"[bold red]error:[/] {result.get('error')}")
        raise typer.Exit(code=1)
    console.print(f"[green]schema ready[/] {result.get('server')}")


@db_app.command("status")
def db_status() -> None:
    """Report whether the audit trail is actually durable.

    Distinguishes "server unreachable" from "server reachable, schema
    missing", because only the second looks healthy to a naive ping.
    """
    from aios.db.session import ledger_status

    status = ledger_status()
    if status["durable"]:
        console.print("[green]durable[/] PostgreSQL ledger ready")
    else:
        console.print("[yellow]degraded[/] falling back to in-memory ledger")
        console.print(f"  reason: {status['reason']}")
        console.print("  [dim]the audit trail will not survive a restart; run `aios db init`[/]")


@app.command()
def serve(
    host: Annotated[str | None, typer.Option(help="Bind address")] = None,
    port: Annotated[int | None, typer.Option(help="Bind port")] = None,
    reload: Annotated[bool, typer.Option(help="Auto-reload on code changes")] = False,
) -> None:
    """Run the FastAPI control API."""
    import uvicorn

    s = _settings()
    bind_host = host or s.api_host
    bind_port = port or s.api_port
    if bind_host not in ("127.0.0.1", "::1", "localhost"):
        err_console.print(
            f"[yellow]warning:[/] binding to {bind_host}. AIOS is local-first; "
            "prefer 127.0.0.1 and do not expose this without authentication."
        )
    console.print(f"AIOS control API on http://{bind_host}:{bind_port} (docs at /docs)")
    uvicorn.run("aios.api:app", host=bind_host, port=bind_port, reload=reload)


@app.callback()
def main() -> None:
    """Read-only AIOS control plane.

    Two kinds of command. The observation commands read the machine directly
    through the gateway, because the operator is the caller and needs no
    grant. `act` is the agent path: it goes through the Security Engine, so
    every action it runs is capability-checked, policy-checked, and logged.
    No command executes a proposed action by any other route.
    """


def run() -> None:
    """Console-script entry point."""
    app()


if __name__ == "__main__":
    run()
