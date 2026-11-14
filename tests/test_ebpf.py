"""eBPF scaffold tests. No privileged probe is executed."""

from __future__ import annotations

from pathlib import Path

from aios.telemetry import (
    PROBE_PATH,
    bpftrace_path,
    parse_event,
    parse_events,
    probe_status,
)


def test_probe_script_exists_and_is_read_only() -> None:
    assert PROBE_PATH.exists()
    script = PROBE_PATH.read_text(encoding="utf-8")
    assert "tracepoint:syscalls:sys_enter_execve" in script
    assert "tracepoint:syscalls:sys_enter_connect" in script
    # Observation probes must not mutate or signal anything.
    assert "signal(" not in script
    assert "override(" not in script
    assert "kill(" not in script


def test_repository_script_matches_the_packaged_copy() -> None:
    repository_copy = PROBE_PATH.parents[2] / "scripts" / "ebpf" / "aios_trace.bt"
    assert repository_copy.exists()
    assert repository_copy.read_text(encoding="utf-8") == PROBE_PATH.read_text(encoding="utf-8")


def test_probe_status_reports_without_running_anything() -> None:
    status = probe_status()
    assert status["requires_root"] is True
    assert status["probe"] == str(PROBE_PATH)
    if bpftrace_path() is None:
        assert status["available"] is False
        assert "bpftrace not installed" in status["reason"]
        assert status["command"] is None
    else:
        assert status["command"].startswith("sudo ")


def test_probe_status_handles_a_missing_script(tmp_path: Path) -> None:
    status = probe_status(tmp_path / "absent.bt")
    assert status["available"] is False
    assert "probe script missing" in status["reason"]


def test_parse_one_event() -> None:
    event = parse_event(
        '{"kind":"execve","pid":42,"comm":"bash","detail":"/bin/ls","timestamp_ns":10}'
    )
    assert event is not None
    assert event.kind == "execve"
    assert event.pid == 42
    assert event.timestamp_ns == 10
    assert event.to_dict()["detail"] == "/bin/ls"


def test_parse_events_skips_noise() -> None:
    text = "\n".join(
        [
            "not json",
            '{"kind":"connect","pid":1,"comm":"curl","detail":"fd=3"}',
            "",
            '{"kind":"exit","pid":2,"comm":"sh"}',
            '{"pid":3}',
        ]
    )
    events = parse_events(text)
    assert [event.kind for event in events] == ["connect", "exit"]
    assert events[1].timestamp_ns is None


def test_parse_event_rejects_bad_types() -> None:
    assert parse_event('{"kind":"execve","pid":"not-a-pid","comm":"x"}') is None
    assert parse_event("[]") is None
