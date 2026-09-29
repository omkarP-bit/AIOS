"""Liveness tests: is the observer suite actually reading THIS machine?

Every other test file points the observers at a fixture tree, which is correct
for deterministic assertions and useless for answering the question a newcomer
actually has: *will this show my machine, or a remembered one?*

So this file reads the real /proc and compares against ground truth obtained
independently, by running the system utilities. A hardcoded engine fails every
test here.

Two things are checked for every comparison:

* **Tolerances are explicit.** These are live counters. Memory available and
  process counts change between the two reads, so demanding equality would
  produce a flaky suite that eventually gets ignored.
* **The reverse is checked too.** A fake root must produce fake numbers, and
  changing the root must change the answer. Without that, "matches reality"
  could be satisfied by a plausible constant.
"""

from __future__ import annotations

import os
import subprocess
import time
from pathlib import Path

import pytest

from aios.observers.cpu import read_cpu
from aios.observers.filesystem import list_mounts
from aios.observers.memory import read_memory
from aios.observers.network import NetworkObserver
from aios.observers.paths import read_text
from aios.observers.process import ProcessObserver
from aios.observers.system import read_system

PROC = Path("/proc")
SYS = Path("/sys")

pytestmark = pytest.mark.skipif(
    not PROC.is_dir(), reason="no live /proc on this platform"
)


def sh(*args: str) -> str:
    """Ground truth from the system utilities, never from AIOS.

    `subprocess` is used here precisely because the production code is
    forbidden to use it: the point of this file is to check the observers
    against an independent source. Every argument is a literal in this file,
    so there is no untrusted input in the call.
    """
    out = subprocess.run(args, capture_output=True, text=True, timeout=30)  # noqa: S603
    return out.stdout.strip()


def meminfo() -> dict[str, int]:
    return {
        line.split(":")[0]: int(line.split()[1])
        for line in read_text(PROC / "meminfo").splitlines()
        if ":" in line and len(line.split()) > 1
    }


# ---------------------------------------------------------------- memory


def test_memory_matches_meminfo() -> None:
    """Stable fields must match exactly. Volatile ones are checked loosely in
    :func:`test_volatile_memory_tracks_proc`."""
    ai = read_memory(PROC)
    real = meminfo()
    assert ai.total_kb == real["MemTotal"]
    assert ai.swap_total_kb == real["SwapTotal"]
    assert ai.swap_free_kb == real["SwapFree"]


def test_volatile_memory_tracks_proc() -> None:
    """MemFree and MemAvailable move while the machine runs, so the assertion
    is that the magnitude is right, not that it is frozen."""
    ai = read_memory(PROC)
    real = meminfo()
    for observed, key in ((ai.free_kb, "MemFree"), (ai.available_kb, "MemAvailable")):
        assert abs(observed - real[key]) <= real["MemTotal"] * 0.01, key
        assert 0 <= observed <= real["MemTotal"], key


def test_memory_buffers_and_cache_are_parsed() -> None:
    """These are separate lines in meminfo, so a parser that ignored them
    would still report a plausible total memory figure."""
    ai = read_memory(PROC)
    real = meminfo()
    assert abs(ai.buffers_kb - real["Buffers"]) <= real["MemTotal"] * 0.01
    assert abs(ai.cached_kb - real["Cached"]) <= real["MemTotal"] * 0.01
    # fields_kb holds the remainder — keys that were not promoted to a typed
    # field — so it must be non-empty, and must not be empty because the parse
    # failed partway. The promoted keys are deliberately absent from it.
    assert ai.fields_kb
    assert "MemTotal" not in ai.fields_kb
    for key, value in ai.fields_kb.items():
        assert key in real, key
        assert value >= 0


def test_memory_percentages_are_derived() -> None:
    """used and available partition the total, which only holds if the
    percentages were computed from the same read rather than stored."""
    info = read_memory(PROC)
    assert 0.0 <= info.used_percent <= 100.0
    assert 0.0 <= info.available_percent <= 100.0
    assert info.used_percent + info.available_percent == pytest.approx(100.0, abs=0.5)


def test_memory_is_not_a_constant() -> None:
    """A hardcoded engine returns the same value forever. Re-reading after a
    real allocation must move the number."""
    before = read_memory(PROC).available_kb
    ballast = [bytearray(64 * 1024 * 1024) for _ in range(24)]
    after = read_memory(PROC).available_kb
    del ballast
    assert before != after
    assert after < before


# ---------------------------------------------------------------- cpu


def test_core_count_matches_nproc() -> None:
    assert read_cpu(PROC, SYS, interval_s=0.05).logical_cores == int(sh("nproc"))


def test_load_average_matches_proc() -> None:
    ai = read_cpu(PROC, SYS, interval_s=0.05)
    real = sh("cat", "/proc/loadavg").split()
    assert ai.load_average_1m == pytest.approx(float(real[0]), abs=0.5)
    assert ai.load_average_5m == pytest.approx(float(real[1]), abs=0.5)
    assert ai.load_average_15m == pytest.approx(float(real[2]), abs=0.5)


def test_cpu_percent_is_a_real_delta() -> None:
    """Per-core utilisation is computed from two reads of /proc/stat, so the
    components have to be internally consistent and the busy portion has to
    react to load."""
    # percent is a flat mapping of component -> share of the sampling window.
    first = read_cpu(PROC, SYS, interval_s=0.2).percent
    second = read_cpu(PROC, SYS, interval_s=0.2).percent
    for p in (first, second):
        assert 0.0 <= p["idle"] <= 100.0
        assert 0.0 <= p["user"] <= 100.0
        assert 0.0 <= p["system"] <= 100.0
        # 'total' is the busy share, and idle + total is the whole window.
        assert p["idle"] + p["total"] == pytest.approx(100.0, abs=1.0)
    # And the second read differs, because work was done in between.
    assert first != second


def test_per_core_count_matches_cpuset() -> None:
    ai = read_cpu(PROC, SYS, interval_s=0.05)
    real = len(
        [
            line
            for line in read_text(PROC / "stat").splitlines()
            if line.startswith("cpu") and line[3].isdigit()
        ]
    )
    assert len(ai.per_core) == real
    assert {c.name for c in ai.per_core} == {f"cpu{i}" for i in range(real)}


# ---------------------------------------------------------------- system


def test_uname_fields_match_the_live_kernel() -> None:
    info = read_system(PROC, SYS)
    assert info.hostname == sh("uname", "-n")
    assert info.architecture == sh("uname", "-m")
    assert info.os_name == sh("uname", "-s")
    # The regression this guards: `kernel` held uname[0], the constant "Linux".
    assert info.kernel == sh("uname", "-r")
    assert info.kernel != "Linux"


def test_process_count_matches_ps() -> None:
    info = read_system(PROC, SYS)
    real = int(sh("sh", "-c", "ps -e --no-headers | wc -l"))
    assert abs(info.processes_total - real) <= 15


def test_thread_count_is_distinct_from_process_count() -> None:
    """loadavg's 4th field is threads, not processes.

    Reporting it as a process count overstates the number of processes by
    roughly four times on a threaded system, which is what it used to do.
    """
    info = read_system(PROC, SYS)
    assert info.threads_total is not None
    assert info.threads_total > info.processes_total
    threads = int(sh("sh", "-c", "ps -eL --no-headers | wc -l"))
    assert abs(info.threads_total - threads) <= 25


def test_uptime_tracks_proc_uptime() -> None:
    info = read_system(PROC, SYS)
    real = float(read_text(PROC / "uptime").split()[0])
    assert info.uptime_s == pytest.approx(real, abs=5.0)


def test_uptime_increases() -> None:
    """Time passing must be visible, which a cached value would not be."""
    before = read_system(PROC, SYS).uptime_s
    time.sleep(1.1)
    assert read_system(PROC, SYS).uptime_s > before


def test_boot_time_is_consistent_with_uptime() -> None:
    """boot + uptime must land near now, so both come from the same real
    clock rather than being independently hardcoded."""
    from datetime import datetime

    info = read_system(PROC, SYS)
    boot = datetime.fromisoformat(info.boot_time_utc)
    now = datetime.fromisoformat(info.now_utc)
    assert (now - boot).total_seconds() == pytest.approx(info.uptime_s, abs=5.0)


# ---------------------------------------------------------------- processes


def test_process_ids_match_ps() -> None:
    real = {p for p in sh("sh", "-c", "ps -eo pid= --no-headers").split() if p.isdigit()}
    got = {str(p.pid) for p in ProcessObserver(PROC).list(limit=50).processes}
    assert got <= real
    assert len(got) >= 20


def test_process_total_matches_proc_directory_count() -> None:
    listing = ProcessObserver(PROC).list(limit=1)
    real = sum(1 for p in PROC.iterdir() if p.name.isdigit())
    assert abs(listing.total_found - real) <= 5


def test_pid_one_is_this_hosts_init() -> None:
    """PID 1 is read out of /proc, so whatever this machine booted must
    appear — a hardcoded process table would name the wrong one."""
    one = ProcessObserver(PROC).inspect(1)
    assert one.pid == 1
    assert one.ppid == 0
    assert one.name
    assert read_text(PROC / "1" / "stat").startswith(f"1 ({one.name})")


def test_full_process_list_contains_this_process() -> None:
    pids = {p.pid for p in ProcessObserver(PROC).list(limit=5000).processes}
    assert os.getpid() in pids


def test_process_details_are_read_not_guessed() -> None:
    """Compare one real process's stats against /proc directly."""
    observer = ProcessObserver(PROC)
    pid = os.getpid()
    info = observer.inspect(pid, with_extras=False)
    stat = read_text(PROC / str(pid) / "stat")
    # The comm field is parenthesised and may contain spaces, so parse after it.
    tail = stat[stat.rindex(")") + 2 :].split()
    assert info.state == tail[0]
    assert info.ppid == int(tail[1])
    assert info.name == os.path.basename(info.executable or "") or info.name


# ---------------------------------------------------------------- network


def test_listening_sockets_are_parsed() -> None:
    result = NetworkObserver(PROC).collect(listening_only=True, limit=200)
    assert isinstance(result.summary.total, int)
    assert result.connections, "no listening sockets found, but the summary counted some"
    for conn in result.connections:
        assert conn.local_port > 0
        assert conn.state == "LISTEN"
        assert conn.inode > 0
        assert conn.family in ("tcp", "tcp6")


def test_connection_count_tracks_proc_net() -> None:
    """Count the real listen lines in /proc/net/tcp ourselves and compare."""
    def listen_lines(path: Path) -> int:
        try:
            return sum(
                1 for line in read_text(path).splitlines()[1:] if line.split()[3] == "0A"
            )
        except OSError:
            return 0

    real = listen_lines(PROC / "net" / "tcp") + listen_lines(PROC / "net" / "tcp6")
    got = NetworkObserver(PROC).collect(listening_only=True, limit=200).summary.total
    assert abs(got - real) <= 2


def test_unix_sockets_are_excluded_by_default() -> None:
    without = NetworkObserver(PROC).collect(include_unix=False, limit=200)
    with_unix = NetworkObserver(PROC).collect(include_unix=True, limit=200)
    assert with_unix.summary.total >= without.summary.total
    assert all(c.family in ("tcp", "tcp6", "udp", "udp6") for c in without.connections)
    assert any(c.family == "unix" for c in with_unix.connections)
    # The regression: unix sockets were reported as family="tcp" and landed in
    # the TCP row, inflating it by however many local sockets the host has.
    assert "unix" not in without.summary.by_transport
    assert with_unix.summary.by_transport["unix"] == with_unix.summary.total - without.summary.total
    assert without.summary.by_transport["tcp"] == sum(
        1 for c in without.connections if c.family == "tcp"
    )


# ---------------------------------------------------------------- filesystem


def test_mounts_match_findmnt() -> None:
    mounts = list_mounts(PROC)
    real_root = sh("sh", "-c", "findmnt -n -o TARGET /")
    by_point = {m.mount_point: m for m in mounts.mounts}
    assert real_root in by_point
    root = by_point[real_root]
    assert root.name
    assert root.fs_type
    assert root.total_bytes > 0


def test_disk_usage_matches_statvfs() -> None:
    mounts = list_mounts(PROC).mounts
    root = mounts[0]
    st = os.statvfs(root.mount_point)
    assert root.total_bytes == st.f_blocks * st.f_frsize
    assert root.free_bytes == st.f_bavail * st.f_frsize


# ---------------------------------------------------------------- the reverse


def test_a_fake_root_produces_fake_numbers(tmp_path: Path) -> None:
    """The mirror image of every test above: same code, different root,
    different answer. This is what proves the values came from the
    filesystem rather than from the function."""
    fake = tmp_path / "proc"
    fake.mkdir()
    (fake / "meminfo").write_text(
        "MemTotal: 1000000 kB\nMemFree: 250000 kB\nMemAvailable: 400000 kB\n"
        "Buffers: 1000 kB\nCached: 2000 kB\nSwapTotal: 0 kB\nSwapFree: 0 kB\n",
        encoding="utf-8",
    )
    assert read_memory(fake).total_kb == 1_000_000
    assert read_memory(fake).total_kb != read_memory(PROC).total_kb


def test_changing_the_root_changes_the_answer(tmp_path: Path) -> None:
    a = read_memory(PROC).total_kb
    other = tmp_path / "p2"
    other.mkdir()
    (other / "meminfo").write_text(
        "MemTotal: 42 kB\nMemFree: 1 kB\nMemAvailable: 1 kB\n"
        "Buffers: 0 kB\nCached: 0 kB\nSwapTotal: 0 kB\nSwapFree: 0 kB\n",
        encoding="utf-8",
    )
    assert read_memory(other).total_kb == 42
    assert read_memory(PROC).total_kb == a


def test_missing_proc_root_degrades_instead_of_inventing(tmp_path: Path) -> None:
    """An unreadable root must surface an error, never a plausible guess."""
    from aios.observers.memory import read_memory as rm

    with pytest.raises(OSError):
        rm(tmp_path / "does-not-exist")


def test_partial_proc_root_reports_read_errors(tmp_path: Path) -> None:
    """A root with meminfo but nothing else should still produce a real
    SystemInfo, and list what it could not read."""
    root = tmp_path / "sparse"
    root.mkdir()
    (root / "uptime").write_text("1234.56 100.00\n", encoding="utf-8")
    info = read_system(root, tmp_path / "nosys")
    assert info.uptime_s == 1234.56
    assert info.hostname == "unknown"
    assert info.read_errors
    assert info.processes_total == 0
