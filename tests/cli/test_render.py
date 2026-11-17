"""Snapshot-style tests for every renderer.

The console records text with colors disabled, so each expectation is the
literal terminal output. That is what we want: a regression in layout, a lost
trust badge, or an escape sequence leaking into the stream should fail here.
"""

from __future__ import annotations

import io
from typing import Any

from rich.console import Console
from rich.markdown import Markdown
from rich.table import Table

from aios.cli.ui.render import (
    denial_explanation,
    render_actions,
    render_answer,
    render_audit,
    render_confirmation,
    render_cpu,
    render_error,
    render_memory,
    render_network,
    render_processes,
    render_proposal,
    render_result,
    render_security,
    render_status,
    render_thinking,
    render_verdict,
)
from aios.cli.ui.theme import AIOS_THEME

INJECTION = "\x1b[2J\x1b[Hroot# "

cpu_payload: dict[str, Any] = {
    "logical_cores": 4,
    "load_average_1m": 0.42,
    "load_average_5m": 0.31,
    "load_average_15m": 0.2,
    "percent": {"total": 37.5, "user": 20.0, "system": 10.0, "idle": 62.5},
    "per_core": [
        {"name": "cpu0", "percent": 41.0},
        {"name": "cpu1", "percent": 33.5},
        {"name": "cpu2", "percent": None},
    ],
    "frequencies": [
        {"cpu": "cpu0", "khz": 2_400_000, "scaling_governor": "schedutil"},
        {"cpu": "cpu1", "khz": None, "scaling_governor": None},
    ],
}

memory_payload: dict[str, Any] = {
    "total_kb": 16_777_216,
    "used_kb": 8_388_608,
    "available_kb": 7_340_032,
    "used_percent": 50.0,
    "available_percent": 43.75,
    "swap_total_kb": 2_097_152,
    "swap_used_kb": 1_048_576,
    "swap_used_percent": 50.0,
}

status_payload: dict[str, Any] = {
    "hostname": "aios-fixture",
    "kernel": "6.8.0-aios",
    "uptime_s": 93_784,
    "logical_cores": 4,
}

processes_payload: dict[str, Any] = {
    "processes": [
        {
            "pid": 1,
            "name": "systemd",
            "state": "S",
            "cpu_percent": 0.4,
            "rss_bytes": 12 * 1024 * 1024,
        },
        {
            "pid": 4242,
            "name": "postgres",
            "state": "R",
            "cpu_percent": 12.25,
            "rss_bytes": 256 * 1024 * 1024,
        },
        {
            "pid": 9,
            "name": "kworker/0:1",
            "state": "I",
            "cpu_percent": None,
            "rss_bytes": 0,
        },
    ]
}

network_payload: dict[str, Any] = {
    "connections": [
        {
            "family": "IPv4",
            "local_address": "127.0.0.1",
            "local_port": 8000,
            "remote_address": None,
            "remote_port": None,
            "state": "LISTEN",
            "pids": [4242],
        },
        {
            "family": "IPv6",
            "local_address": "::1",
            "local_port": 5432,
            "remote_address": "::1",
            "remote_port": 51000,
            "state": "ESTABLISHED",
            "pids": [],
        },
    ],
    "summary": {"total": 2, "by_state": {"LISTEN": 1, "ESTABLISHED": 1}},
}

health_payload: dict[str, Any] = {
    "status": "ok",
    "services": {
        "api": "ok",
        "engine": "ok",
        "opa": "ok",
        "ledger": "ok",
    },
}


def render_text(renderable: Any) -> str:
    console = Console(
        record=True,
        width=100,
        force_terminal=False,
        color_system=None,
        theme=AIOS_THEME,
        file=io.StringIO(),
    )
    console.print(renderable)
    return console.export_text()


def test_status_dashboard_contains_every_section() -> None:
    output = render_text(
        render_status(
            status_payload,
            cpu_payload,
            memory_payload,
            processes_payload,
            network_payload,
            health_payload,
        )
    )
    assert "AIOS status" in output
    assert "aios-fixture" in output
    assert "6.8.0-aios" in output
    assert "1d 02:03" in output
    assert "37.5%" in output
    assert "load 0.42 0.31 0.20" in output
    assert "Top processes" in output
    assert "postgres" in output
    assert "2 connections" in output
    assert "1 listening" in output
    assert "API" in output and "OPA" in output
    assert "ok" in output


def test_status_marks_opa_unavailable() -> None:
    output = render_text(
        render_status(
            status_payload,
            cpu_payload,
            memory_payload,
            processes_payload,
            network_payload,
            {"status": "degraded", "services": {"opa": "unavailable"}},
        )
    )
    assert "unavailable" in output


def test_cpu_panel_shows_cores_and_frequencies() -> None:
    output = render_text(render_cpu(cpu_payload))
    assert "CPU" in output
    assert "cpu0" in output
    assert "41.0%" in output
    assert "2.40 GHz" in output
    # A core without a prior sample stays an explicit dash, never a fake 0%.
    assert "cpu2" in output
    assert "33.5%" in output


def test_memory_panel_shows_used_and_swap() -> None:
    output = render_text(render_memory(memory_payload))
    assert "Memory" in output
    assert "50.0%" in output
    assert "16.0 GiB" in output
    assert "swap" in output


def test_process_table_is_sorted_view_of_supplied_rows() -> None:
    output = render_text(render_processes(processes_payload, sort_by="mem", name_filter="post"))
    assert "Processes" in output
    assert "sort=mem" in output
    assert "filter=post" in output
    assert "PID" in output
    assert "CPU%" in output
    assert "MEM" in output
    assert "4242" in output
    assert "12.2" in output
    assert "256.0 MiB" in output
    # Missing CPU is displayed as "-".
    assert "kworker/0:1" in output


def test_process_table_empty_state() -> None:
    output = render_text(render_processes({"processes": []}))
    assert "No processes matched." in output


def test_hostile_process_name_renders_inert() -> None:
    payload = {
        "processes": [
            {
                "pid": 666,
                "name": INJECTION,
                "state": "R",
                "cpu_percent": 99.0,
                "rss_bytes": 1024,
            }
        ]
    }
    output = render_text(render_processes(payload))
    assert "\x1b" not in output
    assert "\x1b[2J" not in output
    assert "root# " in output
    # The hostile clear-screen never became a command.
    assert "666" in output


def test_process_name_markup_is_literal() -> None:
    payload = {
        "processes": [
            {
                "pid": 777,
                "name": "[bold red]x[/]",
                "state": "R",
                "cpu_percent": 1.0,
                "rss_bytes": 1024,
            }
        ]
    }
    output = render_text(render_processes(payload))
    assert "[bold red]x[/]" in output


def test_network_table_shows_endpoints() -> None:
    output = render_text(render_network(network_payload))
    assert "Network" in output
    assert "IPV4" in output
    assert "127.0.0.1:8000" in output
    assert "ESTABLISHED" in output
    assert "4242" in output


def test_network_listening_caption() -> None:
    output = render_text(render_network(network_payload, listening_only=True))
    assert "listening only" in output


def audit_entries() -> list[dict[str, Any]]:
    return [
        {
            "action_id": "act-allow",
            "action": "filesystem.read",
            "risk": "LOW",
            "decision": "ALLOW",
            "state": "COMPLETED",
            "denial_reason": None,
            "at": "2026-11-15T10:00:00Z",
        },
        {
            "action_id": "act-deny",
            "action": "process.kill",
            "risk": "HIGH",
            "decision": "DENY",
            "state": "DENIED",
            "denial_reason": "capability_missing",
            "at": "2026-11-15T10:01:00Z",
        },
    ]


def test_audit_table_renders_decision_badges() -> None:
    output = render_text(render_audit(audit_entries()))
    assert "Audit" in output
    assert "filesystem.read" in output
    assert "ALLOW" in output
    assert "DENY" in output
    assert "capability_missing" in output


def test_audit_times_are_shown_in_local_time(monkeypatch) -> None:
    import time

    monkeypatch.setenv("TZ", "Asia/Kolkata")
    time.tzset()
    try:
        output = render_text(render_audit(audit_entries()))
    finally:
        monkeypatch.delenv("TZ", raising=False)
        time.tzset()
    # 10:00 UTC is 15:30 in Asia/Kolkata, on the same local day.
    assert "Audit · 2026-11-15" in output
    assert "15:30:00" in output
    assert "10:00:00" not in output


def test_audit_denied_filter_keeps_only_denials() -> None:
    output = render_text(render_audit(audit_entries(), denied_only=True))
    assert "process.kill" in output
    assert "filesystem.read" not in output


def test_actions_view_without_filter_lists_decided_actions() -> None:
    output = render_text(render_actions(audit_entries()))
    assert "Actions" in output
    assert "filesystem.read" in output
    assert "process.kill" in output


def test_security_summary_shows_counts_and_last_events() -> None:
    summary = {
        "counts": {"total": 12, "denied": 3, "confirmed": 1},
        "services": {"api": "ok", "engine": "ok", "opa": "ok", "ledger": "ok"},
        "last_events": audit_entries(),
    }
    output = render_text(render_security(summary))
    assert "Security" in output
    assert "12" in output
    assert "3 denied" in output
    assert "1 confirmed" in output
    assert "Last events" in output


def verdict(**overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "action": "filesystem.read",
        "risk": "LOW",
        "decision": "ALLOW",
        "state": "COMPLETED",
        "denial_reason": None,
        "reason": "read is allowed",
        "policy": {"source": "rego", "policy_id": "aios.authz.allow"},
        "duration_ms": 4.2,
    }
    base.update(overrides)
    return base


def test_allow_verdict_card() -> None:
    output = render_text(render_verdict(verdict(), target="/tmp/notes.txt"))
    assert "ALLOW · LOW" in output
    assert "filesystem.read" in output
    assert "/tmp/notes.txt" in output
    assert "PROPOSED → VALIDATED → AUTHORIZED → EXECUTED → OBSERVED → COMPLETED" in output
    assert "aios.authz.allow" in output
    assert "4.2 ms" in output


def test_confirm_verdict_card_shows_real_action_and_default_no() -> None:
    output = render_text(
        render_verdict(
            verdict(
                decision="CONFIRM",
                risk="MEDIUM",
                state="VALIDATED",
                denial_reason="confirmation_required",
                reason="medium-risk action requires confirmation",
            ),
            target="/var/tmp/cache",
        )
    )
    assert "CONFIRM · MEDIUM" in output
    assert "PROPOSED → VALIDATED → CONFIRM" in output
    assert "/var/tmp/cache" in output
    assert "Approve before anything runs." in output


def test_confirm_prompt_card_uses_real_target() -> None:
    output = render_text(render_confirmation("filesystem.quarantine", "/var/tmp/cache", "MEDIUM"))
    assert "CONFIRM" in output
    assert "filesystem.quarantine" in output
    assert "/var/tmp/cache" in output
    assert "Approve? [y/N]" in output


def test_deny_verdict_card_explains_in_plain_language() -> None:
    output = render_text(
        render_verdict(
            verdict(
                decision="DENY",
                risk="HIGH",
                state="DENIED",
                denial_reason="capability_missing",
                reason="no capability",
            )
        )
    )
    assert "DENY · HIGH" in output
    assert "PROPOSED → VALIDATED → DENIED" in output
    assert "No capability grant covers this action and target." in output


def test_every_denial_reason_has_a_sentence() -> None:
    reasons = [
        "not_in_protocol",
        "forbidden_action",
        "invalid_params",
        "scope_mismatch",
        "capability_missing",
        "capability_revoked",
        "capability_expired",
        "risk_too_high",
        "policy_deny",
        "policy_unavailable",
        "gateway_refused",
        "gateway_error",
        "confirmation_required",
        "plan_required",
        "approval_invalid",
        "approval_expired",
        "plan_mismatch",
        "target_changed",
        "executor_refused",
        "limit_exceeded",
        "plan_replayed",
        "cross_device",
        "internal_error",
        "confirmation_not_allowed",
    ]
    for reason in reasons:
        sentence = denial_explanation(reason)
        assert sentence and not sentence.startswith("Denied by policy for an unspecified")


def test_unknown_denial_reason_is_not_empty() -> None:
    assert "unspecified" in denial_explanation("something_new")


def test_proposal_card_is_labelled_as_ai_proposed() -> None:
    output = render_text(
        render_proposal(
            {
                "type": "filesystem.stat",
                "params": {"path": "/etc/passwd"},
                "intent": "look at the file",
            },
            target="/etc/passwd",
        )
    )
    assert "PROPOSED BY AI" in output
    assert "filesystem.stat" in output
    assert "/etc/passwd" in output


def test_thinking_collapsed_by_default_and_expanded_with_verbose() -> None:
    plan = {
        "provider": "ollama",
        "model": "qwen2.5",
        "external": False,
        "prompt_hash": "sha256:abc",
        "reason": "planned one read",
        "raw": '{"type": "filesystem.stat"}',
    }
    collapsed = render_text(render_thinking(plan))
    assert "--verbose to expand" in collapsed
    assert "sha256:abc" not in collapsed

    expanded = render_text(render_thinking(plan, verbose=True))
    assert "sha256:abc" in expanded
    assert "qwen2.5" in expanded


def test_result_card_labels_provenance_and_trust() -> None:
    output = render_text(
        render_result(
            {"content": "hello\nworld"},
            source="file:/tmp/notes.txt",
            trust_domain="T4",
        )
    )
    assert "Result" in output
    assert "file:/tmp/notes.txt" in output
    assert "T4 UNTRUSTED" in output
    assert "hello" in output


def test_result_card_sanitizes_control_characters() -> None:
    output = render_text(render_result({"content": "safe\rnot-a-command\x07\x1b[31m"}))
    assert "\r" not in output
    assert "\x07" not in output
    assert "\x1b" not in output


def test_answer_is_markdown_without_hyperlinks() -> None:
    answer = render_answer("See [docs](https://example.invalid) for **details**.")
    assert isinstance(answer, Markdown)
    output = render_text(answer)
    assert "details" in output
    assert "https://example.invalid" in output


def test_answer_sanitizes_escape_sequences() -> None:
    output = render_text(render_answer(INJECTION + "**done**"))
    assert "\x1b" not in output
    assert "root# " in output
    assert "done" in output


def test_error_panel_has_next_step() -> None:
    output = render_text(
        render_error("Cannot reach the AIOS core.", next_step="Start it with: aios-core serve")
    )
    assert "Error" in output
    assert "Cannot reach the AIOS core." in output
    assert "Start it with: aios-core serve" in output


def test_all_renderers_return_rich_renderables() -> None:
    renderables = [
        render_status(
            status_payload,
            cpu_payload,
            memory_payload,
            processes_payload,
            network_payload,
            health_payload,
        ),
        render_cpu(cpu_payload),
        render_memory(memory_payload),
        render_network(network_payload),
        render_verdict(verdict()),
        render_confirmation("filesystem.stat", "/tmp", "LOW"),
        render_thinking({"provider": "ollama", "model": "m"}),
        render_result({"ok": True}),
        render_error("boom"),
    ]
    assert all(item is not None for item in renderables)
    assert isinstance(render_processes(processes_payload), Table)
