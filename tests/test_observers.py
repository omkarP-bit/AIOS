"""Observer tests against the fixture procfs/sysfs trees."""

from __future__ import annotations

from pathlib import Path

import pytest

from aios.observers.cpu import CpuFrequency, CpuObserver, parse_stat
from aios.observers.filesystem import (
    _unescape,
    check_readable,
    is_sensitive,
    list_mounts,
    parse_mounts,
    stat_path,
)
from aios.observers.memory import parse_meminfo, read_memory
from aios.observers.network import (
    NetworkObserver,
    parse_addr,
    parse_socket_table,
    parse_unix_table,
)
from aios.observers.paths import PathEscapeError, read_text, resolve_under
from aios.observers.process import (
    ProcessNotFound,
    ProcessObserver,
    parse_status,
)
from aios.observers.process import (
    parse_stat as parse_process_stat,
)
from aios.observers.system import read_system

# ---------------------------------------------------------------- cpu


def test_parse_stat_extracts_aggregate_and_cores() -> None:
    text = (Path(__file__).parent / "fixtures" / "proc" / "stat").read_text()
    aggregate, cores = parse_stat(text)
    assert aggregate.user == 1000
    assert aggregate.idle == 80000
    assert len(cores) == 2
    assert {name for name, _ in cores} == {"cpu0", "cpu1"}


def test_parse_stat_rejects_missing_aggregate() -> None:
    with pytest.raises(ValueError, match="aggregate"):
        parse_stat("cpu0 1 2 3 4\nintr 1\n")


def test_cpu_observer_reports_percentages_after_two_samples(proc_root: Path) -> None:
    observer = CpuObserver(proc_root)
    first = observer.collect(interval_s=0.0)
    assert first.logical_cores == 2
    assert first.load_average_1m == 0.42
    # Identical fixture samples => zero deltas, not a crash or a NaN.
    assert first.percent is not None
    assert first.percent["total"] == 0.0
    assert all(0.0 <= v <= 100.0 for v in first.percent.values())


def test_cpu_observer_first_call_without_baseline_reports_none(proc_root: Path) -> None:
    observer = CpuObserver(proc_root)
    observer.prime()
    result = observer.collect(interval_s=0.0)
    assert result.percent is not None


def test_cpu_percentages_stay_in_range_under_fake_jumps(proc_root: Path) -> None:
    observer = CpuObserver(proc_root)
    observer.prime()
    # Monotonic increase, so the delta is positive and bounded.
    for _ in range(3):
        result = observer.collect(interval_s=0.0)
        if result.percent:
            assert 0.0 <= result.percent["total"] <= 100.0


def test_cpu_frequencies_from_sysfs(proc_root: Path, sys_root: Path) -> None:
    observer = CpuObserver(proc_root, sys_root)
    freqs = observer._read_frequencies()
    assert {f.cpu for f in freqs} == {"cpu0", "cpu1"}
    assert all(f.khz == 2400000 for f in freqs)
    assert all(f.scaling_governor == "powersave" for f in freqs)


def test_frequency_unit_conversion() -> None:
    """sysfs reports kHz. Dividing by 1e3 gives MHz, not GHz.

    The CLI once did exactly that and labelled the result "GHz", so a 4.4 GHz
    CPU was reported as running at 4400 GHz.
    """
    f = CpuFrequency(cpu="cpu0", khz=4_400_000)
    assert f.mhz == 4400.0
    assert f.ghz == 4.4
    assert f.human == "4.40 GHz"
    # The exact failure being guarded: 4400000/1000 mislabelled as GHz.
    assert f.khz / 1000 != f.ghz


def test_frequency_human_picks_a_readable_unit() -> None:
    """A CPU idles around 400 MHz and boosts to 4.4 GHz, so a single unit
    either wastes width (MHz) or precision (GHz)."""
    assert CpuFrequency(cpu="cpu0", khz=400_000).human == "400 MHz"
    assert CpuFrequency(cpu="cpu0", khz=996_000).human == "996 MHz"
    assert CpuFrequency(cpu="cpu0", khz=1_000_000).human == "1.00 GHz"
    assert CpuFrequency(cpu="cpu0", khz=4_400_000).human == "4.40 GHz"
    # A 900 MHz part is still MHz, not "0.90 GHz".
    assert CpuFrequency(cpu="cpu0", khz=900_000).human == "900 MHz"


def test_frequency_absent_reads_as_dash() -> None:
    f = CpuFrequency(cpu="cpu0")
    assert f.khz is None
    assert f.mhz is None
    assert f.ghz is None
    assert f.human == "-"


# ---------------------------------------------------------------- memory


def test_parse_meminfo_converts_mb_and_kb() -> None:
    fields = parse_meminfo("MemTotal: 1000 kB\nHugeTotalSize: 2 mB\nBogus: x kB\n")
    assert fields["MemTotal"] == 1000
    assert fields["HugeTotalSize"] == 2048
    assert "Bogus" not in fields


def test_read_memory_derives_used_from_available(proc_root: Path) -> None:
    mem = read_memory(proc_root)
    assert mem.total_kb == 16_307_636
    assert mem.available_kb == 5_510_288
    assert mem.used_kb == mem.total_kb - mem.available_kb
    assert 0 < mem.used_percent < 100
    assert mem.used_percent + mem.available_percent == pytest.approx(100.0, abs=0.01)
    # No swap in the fixture.
    assert mem.swap_used_percent == 0.0


def test_memory_rejects_incomplete_meminfo() -> None:
    from aios.observers.memory import _meminfo_model

    with pytest.raises(ValueError, match="missing required"):
        _meminfo_model({"MemTotal": 100})


def test_memory_survives_zero_total() -> None:
    from aios.observers.memory import _meminfo_model

    model = _meminfo_model(
        {
            "MemTotal": 0,
            "MemFree": 0,
            "MemAvailable": 0,
            "Buffers": 0,
            "Cached": 0,
            "SwapTotal": 0,
            "SwapFree": 0,
        }
    )
    assert model.used_percent == 0.0


# ---------------------------------------------------------------- process


def test_parse_process_stat_handles_spaces_and_parens_in_comm() -> None:
    text = (Path(__file__).parent / "fixtures" / "proc" / "7777" / "stat").read_text()
    parsed = parse_process_stat(text)
    assert parsed["comm"] == "evil (script)"
    assert parsed["pid"] == 7777
    assert parsed["state"] == "D"
    assert parsed["ppid"] == 4312


def test_parse_process_stat_rejects_junk() -> None:
    with pytest.raises(ValueError):
        parse_process_stat("not a stat file")


def test_parse_status_extracts_identity() -> None:
    text = (Path(__file__).parent / "fixtures" / "proc" / "4312" / "status").read_text()
    status = parse_status(text)
    assert status["Uid"] == [1000, 1000, 1000, 1000]
    assert status["Threads"] == 48


def test_inspect_returns_hostile_cmdline_as_data(proc_root: Path) -> None:
    """A malicious cmdline is parsed, not executed or interpreted."""
    info = ProcessObserver(proc_root).inspect(7777)
    assert info.name == "evil (script)"
    assert any("rm -rf /" in arg for arg in info.cmdline)
    assert info.state_description.startswith("uninterruptible")
    assert info.io is not None
    assert info.limits.get("Max processes") == 62811
    assert info.limits.get("Max cpu time") == "unlimited"


def test_inspect_rejects_nonpositive_pid(proc_root: Path) -> None:
    observer = ProcessObserver(proc_root)
    for bad in (0, -1, -99999):
        with pytest.raises(ProcessNotFound):
            observer.inspect(bad)


def test_inspect_reports_rss_in_bytes(proc_root: Path) -> None:
    info = ProcessObserver(proc_root).inspect(4313)
    assert info.rss_bytes == 8_000_000 * 4096
    assert info.vsize_bytes == 40_000_000_000


def test_inspect_very_large_pid_does_not_overflow(proc_root: Path) -> None:
    info = ProcessObserver(proc_root).inspect(2_147_483_000)
    assert info.pid == 2_147_483_000
    assert info.vsize_bytes == 4_000_000_000_000


def test_list_skips_unreadable_pids_without_failing(proc_root: Path) -> None:
    result = ProcessObserver(proc_root).list(limit=50)
    assert result.returned <= 50
    assert result.total_found >= 6
    # 9999 has a status file but no usable stat.
    assert any(entry["pid"] == "9999" for entry in result.skipped)


def test_list_rejects_bad_sort_and_limit(proc_root: Path) -> None:
    observer = ProcessObserver(proc_root)
    with pytest.raises(ValueError, match="sort_by"):
        observer.list(sort_by="; rm -rf /")
    with pytest.raises(ValueError, match="limit"):
        observer.list(limit=0)


def test_list_sort_by_memory_puts_ollama_first(proc_root: Path) -> None:
    result = ProcessObserver(proc_root).list(limit=5, sort_by="memory")
    assert result.processes[0].pid == 4313
    rss = [p.rss_bytes for p in result.processes]
    assert rss == sorted(rss, reverse=True)


def test_list_name_filter(proc_root: Path) -> None:
    result = ProcessObserver(proc_root).list(limit=50, name_filter="fire")
    assert {p.name for p in result.processes} == {"firefox"}


def test_list_reports_cpu_unavailable_on_first_pass(proc_root: Path) -> None:
    assert ProcessObserver(proc_root).list(limit=5).cpu_percent_available is False


# ---------------------------------------------------------------- network


def test_parse_addr_v4_is_little_endian() -> None:
    assert parse_addr("0100007F:1F90", "tcp") == ("127.0.0.1", 8080)
    assert parse_addr("00000000:0000", "tcp") == ("0.0.0.0", 0)


def test_parse_addr_v6_is_four_little_endian_words() -> None:
    # ::1 is stored word-swapped, matching real /proc/net/tcp6 output.
    addr, port = parse_addr("00000000000000000000000001000000:0050", "tcp6")
    assert addr == "::1"
    assert port == 80
    assert parse_addr("0" * 32 + ":0000", "tcp6")[0] == "::"


def test_parse_socket_table_reads_states(proc_root: Path) -> None:
    text = read_text(proc_root / "net" / "tcp")
    conns = parse_socket_table(text, "tcp")
    states = {c.state for c in conns}
    assert "LISTEN" in states
    assert "ESTABLISHED" in states
    listener = next(c for c in conns if c.state == "LISTEN" and c.local_port == 8080)
    assert listener.local_address == "127.0.0.1"
    assert listener.remote_address is None


def test_udp_has_no_tcp_state(proc_root: Path) -> None:
    conns = parse_socket_table(read_text(proc_root / "net" / "udp"), "udp")
    assert all(c.state is None for c in conns)


def test_parse_unix_table_handles_abstract_sockets(proc_root: Path) -> None:
    text = read_text(proc_root / "net" / "unix")
    entries = parse_unix_table(text)
    assert len(entries) == 3
    assert entries[0]["path"] == "/run/user/1000/systemd/private"
    assert entries[2]["path"] is None


def test_network_collect_summarises_all_families(proc_root: Path) -> None:
    result = NetworkObserver(proc_root).collect(attribute_pids=False)
    assert result.summary.total > 0
    assert set(result.summary.by_transport) <= {"tcp", "tcp6", "udp", "udp6"}
    assert "LISTEN" in result.summary.by_state


def test_network_listening_only_filter(proc_root: Path) -> None:
    result = NetworkObserver(proc_root).collect(
        attribute_pids=False, listening_only=True
    )
    assert all(c.state == "LISTEN" for c in result.connections)


def test_network_respects_limit_and_flags_truncation(proc_root: Path) -> None:
    result = NetworkObserver(proc_root).collect(attribute_pids=False, limit=2)
    assert len(result.connections) == 2
    assert result.summary.truncated is True


# ---------------------------------------------------------------- filesystem


def test_parse_mounts_decodes_octal_escapes() -> None:
    entries = parse_mounts("/dev/sda1 /mnt/usb\\040backup ext4 rw 0 0\n", {"ext4"})
    assert entries[0].mount_point == "/mnt/usb backup"


def test_parse_mounts_collapsed_duplicate_mount_points() -> None:
    text = (
        "/dev/sda1 /data ext4 rw 0 0\n"
        "/dev/sdb1 /data btrfs ro 0 0\n"
    )
    entries = parse_mounts(text, None)
    assert len(entries) == 1
    assert entries[0].fs_type == "btrfs"


def test_unescape_handles_plain_and_escaped() -> None:
    assert _unescape("/plain/path") == "/plain/path"
    assert _unescape("/a\\040b\\011c") == "/a b\tc"
    assert _unescape("") == ""


def test_list_mounts_filters_pseudo_by_default(proc_root: Path) -> None:
    result = list_mounts(proc_root)
    points = {m.mount_point for m in result.mounts}
    assert "/" in points
    assert "/proc" not in points
    assert "/sys" not in points
    # sshfs is not in the allow-list of real filesystems.
    assert "/mnt/remote" not in points


def test_list_mounts_can_include_pseudo(proc_root: Path) -> None:
    result = list_mounts(proc_root, pseudo=True)
    points = {m.mount_point for m in result.mounts}
    assert "/proc" in points
    assert "/sys" in points


def test_sensitive_prefix_check() -> None:
    assert is_sensitive("/etc/shadow")
    assert is_sensitive("/etc/ssh/sshd_config")
    assert is_sensitive("/dev/mem")
    assert not is_sensitive("/home/user/Downloads/report.pdf")
    assert not is_sensitive("/etc/hostname")


def test_check_readable_blocks_sensitive_and_dirs(tmp_workdir) -> None:
    assert check_readable("/etc/shadow") is not None
    assert check_readable(tmp_workdir) is not None  # directory
    assert check_readable(tmp_workdir / "missing.txt") is not None


def test_check_readable_allows_ordinary_file(tmp_workdir) -> None:
    target = tmp_workdir / "report.txt"
    target.write_text("hello", encoding="utf-8")
    assert check_readable(target) is None


def test_stat_path_reports_missing() -> None:
    meta = stat_path("/nonexistent/path/xyz")
    assert meta.exists is False


def test_stat_path_reports_real_file(tmp_workdir) -> None:
    target = tmp_workdir / "a.txt"
    target.write_text("x" * 10, encoding="utf-8")
    meta = stat_path(target)
    assert meta.exists and meta.is_file and meta.size_bytes == 10


# ---------------------------------------------------------------- system


def test_read_system_aggregates(proc_root: Path, sys_root: Path) -> None:
    info = read_system(proc_root, sys_root)
    assert info.hostname == "aios-fixture"
    assert info.uptime_s == 1234567.89
    assert info.pid_max == 4194304
    assert info.processes_running == 2
    # loadavg's 4th field is 2/431, and 431 is *threads*. The process count
    # comes from the /proc tree instead, which is why these are different
    # numbers and why both are asserted.
    assert info.threads_total == 431
    assert info.processes_total == 10

    # kernel is the *release* (what `uname -r` prints); os_name is the sysname.
    # These were swapped, which made `kernel` report the constant "Linux".
    # They come from os.uname(), so they reflect the live host even when
    # proc_root is a fixture — hostname does not, which is why it is not here.
    import os as _os

    assert info.kernel == _os.uname().release
    assert info.os_name == _os.uname().sysname
    assert info.architecture == _os.uname().machine
    # The regression these guard: `kernel` used to hold uname[0], so it was
    # the string "Linux" on every machine ever built.
    assert info.kernel != "Linux"
    assert info.os_name == "Linux"
    assert info.open_files == 2048
    assert set(info.block_devices) == {"nvme0n1", "sda"}
    assert info.net_devices == ["eth0", "wlan0"]
    assert info.thermal_zones["thermal_zone0:x86_pkg_temp"] == 47.0
    assert info.boot_time_utc is not None


# ---------------------------------------------------------------- path safety


def test_resolve_under_blocks_dotdot_escape(proc_root: Path) -> None:
    with pytest.raises(PathEscapeError):
        resolve_under(proc_root, "../../etc/passwd")


def test_resolve_under_blocks_absolute_component(proc_root: Path) -> None:
    with pytest.raises(PathEscapeError, match="absolute"):
        resolve_under(proc_root, "/etc/shadow")


def test_resolve_under_allows_inner_path(proc_root: Path) -> None:
    assert resolve_under(proc_root, "4312", "stat") == (proc_root / "4312" / "stat").resolve()


def test_read_text_enforces_byte_ceiling(proc_root: Path) -> None:
    with pytest.raises(ValueError, match="exceeds read limit"):
        read_text(proc_root / "meminfo", max_bytes=10)


# ---------------------------------------------------------------- live host


def test_live_proc_observations(proc_root: Path, live_proc_root: Path) -> None:
    """Sanity check that the same code paths work against real /proc."""
    mem = read_memory(live_proc_root)
    assert mem.total_kb > 0
    result = ProcessObserver(live_proc_root).list(limit=5)
    assert result.returned > 0
    net = NetworkObserver(live_proc_root).collect(attribute_pids=False, limit=10)
    assert net.summary.total > 0
