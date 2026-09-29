"""Process observers — ``process.list`` and ``process.inspect(pid)``.

Everything is read from procfs: no signals, no ``/proc`` writes, no ps
subprocess. PIDs can vanish mid-scan (the kernel reclaims them constantly), so
per-process failures are collected as ``skipped`` rather than aborting the
listing.
"""

from __future__ import annotations

import re
import time
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field

from aios.observers.paths import read_text, resolve_under

# /proc/<pid>/stat fields, 1-indexed per proc(5). Field 2 is comm and may
# contain spaces and parentheses, so the name is split out by paren matching
# rather than whitespace.
STAT_FIELDS = (
    "pid",
    "comm",
    "state",
    "ppid",
    "pgrp",
    "session",
    "tty_nr",
    "tpgid",
    "flags",
    "minflt",
    "cminflt",
    "majflt",
    "cmajflt",
    "utime",
    "stime",
    "cutime",
    "cstime",
    "priority",
    "nice",
    "num_threads",
    "itrealvalue",
    "starttime",
    "vsize",
    "rss",
    "rsslim",
    "startcode",
    "endcode",
    "startstack",
    "kstkesp",
    "kstkeip",
    "signal",
    "blocked",
    "sigignore",
    "sigcatch",
    "wchan",
    "nswap",
    "cnswap",
    "exit_signal",
    "processor",
    "rt_priority",
    "policy",
    "delayacct_blkio_ticks",
    "guest_time",
    "cguest_time",
    "start_data",
    "end_data",
    "start_brk",
    "arg_start",
    "arg_end",
    "env_start",
    "env_end",
    "exit_code",
)

CLK_TCK = 100
PAGE_SIZE = 4096

#: Process states worth surfacing to a human, mapped to plain language.
STATE_DESCRIPTION = {
    "R": "running",
    "S": "sleeping (interruptible)",
    "D": "uninterruptible sleep (often I/O wait)",
    "Z": "zombie",
    "T": "stopped (job control)",
    "t": "tracing stop",
    "X": "dead",
    "x": "dead",
    "K": "wakekill",
    "W": "waking",
    "P": "parked",
    "I": "idle",
}

#: States we refuse to inspect further. A zombie or kernel thread has no
#: meaningful user-space identity, and treating one as inspectable invites
#: the AI to build conclusions on nothing.
NON_INSPECTABLE_STATES = frozenset({"Z", "X", "x"})


class ProcessInfo(BaseModel):
    model_config = ConfigDict(extra="forbid")

    pid: int
    ppid: int
    name: str
    state: str
    state_description: str
    uid: int | None = None
    gid: int | None = None
    threads: int | None = None
    vsize_bytes: int | None = None
    rss_bytes: int | None = None
    rss_percent: float | None = None
    cpu_percent: float | None = None
    start_time_utc: str | None = None
    elapsed_s: float | None = None
    cmdline: list[str] = Field(default_factory=list)
    executable: str | None = None
    cwd: str | None = None
    uid_real: int | None = None
    threads_list: list[int] = Field(default_factory=list)
    io: dict[str, int] | None = None
    limits: dict[str, int | str] = Field(default_factory=dict)
    sched: dict[str, float | int] | None = None
    cgroup: str | None = None


class ProcessListResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    processes: list[ProcessInfo]
    total_found: int
    returned: int
    skipped: list[dict[str, str]] = Field(default_factory=list)
    cpu_percent_available: bool = False
    memory_total_kb: int | None = None


class ProcessNotFound(LookupError):
    pass


_STAT_RE = re.compile(r"^(\d+)\s+\((.*)\)\s+(.*)$", re.DOTALL)
_STATUS_RE = re.compile(r"^(\w+):\s+(.*)$")


def parse_stat(text: str) -> dict[str, object]:
    """Parse ``/proc/<pid>/stat``, tolerating spaces and parens inside comm."""
    match = _STAT_RE.match(text.strip())
    if not match:
        raise ValueError("unparsable /proc/<pid>/stat line")
    pid, comm, rest = match.groups()
    values = rest.split()
    if len(values) < 22:
        raise ValueError(f"short /proc/<pid>/stat: {len(values)} fields after comm")

    out: dict[str, object] = {"pid": int(pid), "comm": comm}
    # values[0] is field 3 (state); STAT_FIELDS[2] is 'state'.
    for offset, value in enumerate(values):
        idx = offset + 2
        if idx >= len(STAT_FIELDS):
            break
        name = STAT_FIELDS[idx]
        if name in ("state", "wchan"):
            out[name] = value
        elif name.startswith("exit_signal") or name in ("policy", "startcode", "endcode"):
            try:
                out[name] = int(value, 16) if name == "exit_signal" else int(value)
            except ValueError:
                out[name] = value
        else:
            try:
                out[name] = int(value)
            except ValueError:
                out[name] = value
    return out


def parse_status(text: str) -> dict[str, object]:
    """Parse ``/proc/<pid>/status`` into typed fields."""
    out: dict[str, object] = {}
    for line in text.splitlines():
        m = _STATUS_RE.match(line.strip())
        if not m:
            continue
        key, value = m.group(1), m.group(2).strip()
        if key in ("Uid", "Gid"):
            out[key] = [int(p) for p in value.split() if p.isdigit()]
        elif key in ("PPid", "Threads", "VmSize", "VmRSS", "VmPeak", "VmSwap", "State", "Name"):
            first = value.split("\t")[0].split()[0] if value.split() else ""
            if key == "State":
                out[key] = first
            elif first.rstrip("kB").isdigit():
                out[key] = int(first.rstrip("kB"))
            else:
                out[key] = first
        elif key == "VmPeak" or key == "VmSize" or key == "VmRSS" or key == "VmSwap":
            out[key] = value
        else:
            out[key] = value
    return out


def _parse_cmdline(raw: str) -> list[str]:
    return [part for part in raw.split("\0") if part]


def _boot_time(proc_root: Path) -> float:
    try:
        stat = read_text(resolve_under(proc_root, "stat"))
    except OSError:
        return 0.0
    for line in stat.splitlines():
        if line.startswith("btime"):
            try:
                return float(line.split()[1])
            except (IndexError, ValueError):
                return 0.0
    return 0.0


def _read_io(proc_root: Path, pid: int) -> dict[str, int] | None:
    try:
        text = read_text(resolve_under(proc_root, str(pid), "io"), 8192)
    except (OSError, ValueError):
        return None
    out: dict[str, int] = {}
    for line in text.splitlines():
        if ":" not in line:
            continue
        key, _, value = line.partition(":")
        try:
            out[key.strip()] = int(value.strip())
        except ValueError:
            continue
    return out or None


def _read_sched(proc_root: Path, pid: int) -> dict[str, float | int] | None:
    """Policy/priority facts. Deliberately excludes user-controlled strings."""
    try:
        stat = read_text(resolve_under(proc_root, str(pid), "schedstat"), 1024)
    except OSError:
        return None
    parts = stat.split()
    if not parts:
        return None
    names = ("time_on_cpu_ns", "run_queue_wait_ns", "timeslices")
    out: dict[str, float | int] = {}
    for name, value in zip(names, parts, strict=False):
        try:
            out[name] = int(value)
        except ValueError:
            continue
    return out or None


#: /proc/<pid>/limits is a fixed-width table, not whitespace-delimited,
#: because the label itself contains spaces ("Max cpu time").
LIMIT_COLUMNS = (slice(0, 26), slice(26, 47), slice(47, 68))
LIMIT_LABELS = (
    "Max cpu time",
    "Max file size",
    "Max data size",
    "Max stack size",
    "Max core file size",
    "Max resident set",
    "Max processes",
    "Max open files",
    "Max locked memory",
    "Max address space",
    "Max file locks",
    "Max pending signals",
    "Max msgqueue size",
    "Max nice priority",
    "Max realtime priority",
    "Max realtime timeout",
)


def parse_limits(text: str) -> dict[str, int | str]:
    """Parse the limits table into {label: soft_limit}.

    Only the soft limit is kept. Hard limits describe what the process could
    escalate to, not what it currently may do.
    """
    out: dict[str, int | str] = {}
    for line in text.splitlines():
        if "|" in line:
            label, _, rest = line.partition("|")
            soft = rest.partition("|")[0]
            label = label.strip()
            value = soft.strip()
        else:
            label = line[slice(0, 26)].strip()
            if label not in LIMIT_LABELS:
                continue
            value = line[slice(26, 47)].strip()
        if not label or label == "Limit":
            continue
        if value == "unlimited":
            out[label] = "unlimited"
            continue
        try:
            out[label] = int(value)
        except ValueError:
            continue
    return out


def _read_limits(proc_root: Path, pid: int) -> dict[str, int | str]:
    """Numeric resource limits only. Non-numeric limit text is dropped
    because it is user-controlled and has no place in an authorization view."""
    try:
        text = read_text(resolve_under(proc_root, str(pid), "limits"), 16384)
    except OSError:
        return {}
    return parse_limits(text)


class ProcessObserver:
    """Read-only process introspection over a procfs root."""

    def __init__(self, proc_root: Path) -> None:
        self.proc_root = Path(proc_root)
        self._prev_cpu: dict[int, tuple[float, int]] = {}
        self._boot_time = _boot_time(self.proc_root)

    def list_pids(self) -> list[int]:
        try:
            return sorted(
                int(entry.name)
                for entry in resolve_under(self.proc_root).iterdir()
                if entry.name.isdigit()
            )
        except OSError:
            return []

    def _elapsed(self, starttime_ticks: int | None) -> float | None:
        if starttime_ticks is None or self._boot_time <= 0:
            return None
        now_ticks = time.clock_gettime(time.CLOCK_BOOTTIME) * CLK_TCK
        elapsed = (now_ticks / CLK_TCK) - self._boot_time - (starttime_ticks / CLK_TCK)
        return round(max(elapsed, 0.0), 2)

    def _cpu_percent(self, pid: int, stat: dict[str, object], now: float) -> float | None:
        utime = stat.get("utime")
        stime = stat.get("stime")
        if not isinstance(utime, int) or not isinstance(stime, int):
            return None
        total = utime + stime
        prev = self._prev_cpu.get(pid)
        self._prev_cpu[pid] = (now, total)
        if prev is None:
            return None
        prev_time, prev_total = prev
        delta_ticks = total - prev_total
        if delta_ticks < 0:
            return None
        elapsed = now - prev_time
        if elapsed <= 0:
            return None
        return round(100.0 * (delta_ticks / CLK_TCK) / elapsed, 2)

    def inspect(self, pid: int, with_extras: bool = True) -> ProcessInfo:
        """Detailed view of one process. Raises ProcessNotFound if absent."""
        if pid <= 0:
            raise ProcessNotFound(f"invalid pid: {pid}")
        base = resolve_under(self.proc_root, str(pid))
        try:
            stat_text = read_text(base / "stat", 8192)
        except (OSError, ValueError) as exc:
            raise ProcessNotFound(f"pid {pid} is not readable: {exc}") from exc

        stat = parse_stat(stat_text)
        state = str(stat.get("state", "?"))

        uid = gid = None
        status: dict[str, object] = {}
        try:
            status = parse_status(read_text(base / "status", 32768))
        except (OSError, ValueError):
            pass
        uid_list = status.get("Uid")
        if isinstance(uid_list, list) and uid_list:
            uid = uid_list[0]
        gid_list = status.get("Gid")
        if isinstance(gid_list, list) and gid_list:
            gid = gid_list[0]

        cmdline: list[str] = []
        executable: str | None = None
        cwd: str | None = None
        try:
            cmdline = _parse_cmdline(read_text(base / "cmdline", 131072))
            if cmdline:
                executable = cmdline[0]
        except (OSError, ValueError):
            pass
        if with_extras:
            try:
                cwd = str((base / "cwd").resolve())
            except (OSError, ValueError):
                cwd = None
            try:
                executable = (base / "exe").resolve().name
            except (OSError, ValueError):
                pass

        rss_pages = stat.get("rss")
        rss_bytes = rss_pages * PAGE_SIZE if isinstance(rss_pages, int) else None
        vsize = stat.get("vsize")

        threads: list[int] = []
        try:
            threads = sorted(
                int(t.name) for t in (base / "task").iterdir() if t.name.isdigit()
            )
        except OSError:
            pass

        cgroup = None
        try:
            cgroup = read_text(base / "cgroup", 8192).strip().splitlines()[0][:256]
        except (OSError, IndexError, ValueError):
            pass

        starttime = stat.get("starttime")
        return ProcessInfo(
            pid=pid,
            ppid=int(stat.get("ppid", 0) or 0),
            name=str(stat.get("comm", "")),
            state=state,
            state_description=STATE_DESCRIPTION.get(state, "unknown"),
            uid=uid,
            gid=gid,
            threads=int(stat.get("num_threads", 0) or 0) or None,
            vsize_bytes=vsize if isinstance(vsize, int) else None,
            rss_bytes=rss_bytes,
            cpu_percent=self._cpu_percent(pid, stat, time.monotonic()),
            start_time_utc=None,
            elapsed_s=self._elapsed(starttime if isinstance(starttime, int) else None),
            cmdline=cmdline,
            executable=executable,
            cwd=cwd,
            threads_list=threads,
            io=_read_io(self.proc_root, pid) if with_extras else None,
            limits=_read_limits(self.proc_root, pid) if with_extras else {},
            sched=_read_sched(self.proc_root, pid) if with_extras else None,
            cgroup=cgroup,
        )

    def list(
        self,
        limit: int = 50,
        sort_by: str = "cpu",
        name_filter: str | None = None,
        uid_filter: int | None = None,
        include_cmdline: bool = False,
    ) -> ProcessListResult:
        """Snapshot of processes, sorted and truncated to ``limit``."""
        if limit <= 0:
            raise ValueError("limit must be positive")
        if sort_by not in ("cpu", "memory", "pid", "name"):
            raise ValueError(f"unsupported sort_by: {sort_by}")

        pids = self.list_pids()
        processes: list[ProcessInfo] = []
        skipped: list[dict[str, str]] = []
        cpu_available = False

        for pid in pids:
            try:
                info = self.inspect(pid, with_extras=False)
            except ProcessNotFound as exc:
                skipped.append({"pid": str(pid), "reason": str(exc)[:200]})
                continue
            except Exception as exc:  # unreadable /proc entry, keep going
                skipped.append({"pid": str(pid), "reason": f"{type(exc).__name__}"[:200]})
                continue

            if name_filter and name_filter.lower() not in info.name.lower():
                continue
            if uid_filter is not None and info.uid != uid_filter:
                continue
            if include_cmdline:
                try:
                    info = self.inspect(pid, with_extras=False)
                except ProcessNotFound:
                    continue
            if info.cpu_percent is not None:
                cpu_available = True
            processes.append(info)

        if sort_by == "cpu":
            processes.sort(key=lambda p: (p.cpu_percent or 0.0), reverse=True)
        elif sort_by == "memory":
            processes.sort(key=lambda p: (p.rss_bytes or 0), reverse=True)
        elif sort_by == "name":
            processes.sort(key=lambda p: p.name.lower())
        else:
            processes.sort(key=lambda p: p.pid)

        total = len(processes)
        processes = processes[:limit]
        return ProcessListResult(
            processes=processes,
            total_found=total,
            returned=len(processes),
            skipped=skipped,
            cpu_percent_available=cpu_available,
        )

    def rss_percentages(self, rss_bytes: int) -> float | None:
        from aios.observers.memory import read_memory

        try:
            mem = read_memory(self.proc_root)
        except (OSError, ValueError):
            return None
        if mem.total_kb <= 0:
            return None
        return round(100.0 * (rss_bytes / 1024) / mem.total_kb, 2)
