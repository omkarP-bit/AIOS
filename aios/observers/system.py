"""System observer — hostname, uptime, kernel, boot time, load, disks.

Aggregates the small ``/proc`` and ``/sys`` reads that describe the machine as
a whole, so ``system.status`` is one call.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field

from aios.observers.paths import read_int, read_text, resolve_under


class SystemInfo(BaseModel):
    model_config = ConfigDict(extra="forbid")

    hostname: str
    kernel: str | None = None
    kernel_version: str | None = None
    architecture: str | None = None
    os_name: str | None = None
    uptime_s: float | None = None
    boot_time_utc: str | None = None
    now_utc: str
    pid_max: int | None = None
    page_size: int | None = None
    processes_running: int | None = None
    processes_total: int | None = None
    threads_total: int | None = None
    open_files: int | None = None
    logical_cores: int | None = None
    block_devices: list[str] = Field(default_factory=list)
    net_devices: list[str] = Field(default_factory=list)
    thermal_zones: dict[str, float] = Field(default_factory=dict)
    read_errors: list[str] = Field(default_factory=list)


def _read_uptime(proc_root: Path) -> tuple[float | None, float | None]:
    """Return (uptime_seconds, idle_seconds)."""
    try:
        text = read_text(resolve_under(proc_root, "uptime"), 256)
    except OSError:
        return None, None
    parts = text.split()
    if not parts:
        return None, None
    try:
        return round(float(parts[0]), 2), round(float(parts[1]), 2)
    except (ValueError, IndexError):
        return None, None


def _boot_time_utc(proc_root: Path) -> str | None:
    try:
        text = read_text(resolve_under(proc_root, "stat"))
    except OSError:
        return None
    for line in text.splitlines():
        if line.startswith("btime"):
            try:
                return datetime.fromtimestamp(int(line.split()[1]), tz=UTC).isoformat()
            except (IndexError, ValueError, OSError):
                return None
    return None


def _cpu_counts() -> int | None:
    """Online CPUs, from sched_getaffinity if available, else os.cpu_count."""
    import os

    try:
        return len(os.sched_getaffinity(0))
    except (AttributeError, OSError):
        return os.cpu_count()


def _block_devices(sys_root: Path) -> list[str]:
    base = resolve_under(sys_root, "block")
    try:
        return sorted(
            entry.name
            for entry in base.iterdir()
            if entry.name.startswith(("sd", "nvme", "vd", "hd", "mmcblk", "dm-"))
        )
    except OSError:
        return []


def _net_devices(sys_root: Path) -> list[str]:
    base = resolve_under(sys_root, "class", "net")
    try:
        return sorted(entry.name for entry in base.iterdir() if entry.name != "lo")
    except OSError:
        return []


def _thermal_zones(sys_root: Path) -> dict[str, float]:
    base = resolve_under(sys_root, "class", "thermal")
    zones: dict[str, float] = {}
    try:
        entries = sorted(base.iterdir())
    except OSError:
        return zones
    for zone in entries:
        if not zone.name.startswith("thermal_zone"):
            continue
        try:
            raw = read_text(zone / "temp", 64).strip()
            millidegrees = int(raw)
        except (OSError, ValueError):
            continue
        kind = "unknown"
        try:
            kind = read_text(zone / "type", 64).strip() or "unknown"
        except OSError:
            pass
        zones[f"{zone.name}:{kind}"] = round(millidegrees / 1000.0, 1)
    return zones


def read_system(proc_root: Path, sys_root: Path) -> SystemInfo:
    proc_root, sys_root = Path(proc_root), Path(sys_root)
    errors: list[str] = []

    def safe(name: str, fn):
        try:
            return fn()
        except OSError as exc:
            errors.append(f"{name}: {type(exc).__name__}")
            return None

    hostname = safe(
        "hostname",
        lambda: read_text(resolve_under(proc_root, "sys/kernel/hostname"), 256).strip(),
    ) or "unknown"

    uname: list[str] = []
    try:
        import os as _os

        uname = list(_os.uname())
    except (AttributeError, OSError):
        uname = []

    uptime_s, _ = _read_uptime(proc_root)
    running, threads_total = _loadavg_counts(proc_root)
    total_procs = _count_processes(proc_root)

    return SystemInfo(
        hostname=hostname,
        # os.uname() is a namedtuple: (sysname, nodename, release, version, machine).
        # `release` is what `uname -r` prints and is the number people mean by
        # "kernel version"; `version` is the full build string.
        os_name=uname[0] if uname else None,
        kernel=uname[2] if uname else None,
        kernel_version=uname[3] if uname else None,
        architecture=uname[4] if uname else None,
        uptime_s=uptime_s,
        boot_time_utc=_boot_time_utc(proc_root),
        now_utc=datetime.now(UTC).isoformat(),
        pid_max=safe("pid_max", lambda: read_int(resolve_under(proc_root, "sys/kernel/pid_max"))),
        page_size=safe("page_size", _page_size),
        processes_running=running,
        processes_total=total_procs,
        threads_total=threads_total,
        open_files=safe(
            "open_files", lambda: _first_int(resolve_under(proc_root, "sys/fs/file-nr"))
        ),
        logical_cores=_cpu_counts(),
        block_devices=_block_devices(sys_root),
        net_devices=_net_devices(sys_root),
        thermal_zones=_thermal_zones(sys_root),
        read_errors=errors,
    )


def _loadavg_counts(proc_root: Path) -> tuple[int | None, int | None]:
    """``(runnable, threads_total)`` from /proc/loadavg's 4th field.

    The field is ``runnable/total``, and **total counts threads, not
    processes** — on this host loadavg reports ~1416 while ``ps -e`` reports
    ~347. It is returned here as the thread count precisely because that is
    what it is; the process count is counted from the /proc tree instead, in
    :func:`_count_processes`. Getting this backwards is how a system panel
    ends up reporting three times the processes that exist.
    """
    try:
        text = read_text(resolve_under(proc_root, "loadavg"), 256)
    except OSError:
        return None, None
    parts = text.split()
    if len(parts) < 4 or "/" not in parts[3]:
        return None, None
    runnable, _, total = parts[3].partition("/")
    try:
        return int(runnable), int(total)
    except ValueError:
        return None, None


def _count_processes(proc_root: Path) -> int | None:
    """Number of process directories currently in /proc.

    Counted rather than derived, because the only free source of this number
    is the directory listing itself.
    """
    try:
        return sum(1 for entry in proc_root.iterdir() if entry.name.isdigit())
    except OSError:
        return None


def _first_int(path: Path) -> int | None:
    """First whitespace-separated integer in a file (file-nr is 'a b c')."""
    try:
        text = read_text(path, 256)
    except OSError:
        return None
    first = text.split()[0] if text.split() else ""
    try:
        return int(first)
    except ValueError:
        return None


def _page_size() -> int | None:
    import os as _os

    try:
        return _os.sysconf("SC_PAGE_SIZE")
    except (ValueError, OSError, AttributeError):
        return None
