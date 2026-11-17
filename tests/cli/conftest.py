"""Fixtures for CLI tests: a fake core client and a fake model provider.

The fakes return the same shapes the Go core and an OpenAI-style provider
return, so the tests exercise the real rendering and error paths without a
network or a model.
"""

from __future__ import annotations

from typing import Any

import pytest

from aios.ai.catalog import Catalog

SCHEMA = {
    "protocol_version": "0.7.0",
    "allowed_actions": ["filesystem.read", "process.list", "system.memory", "system.status"],
    "forbidden_actions": ["process.kill", "shell.exec"],
    "params_schema": {
        "filesystem.read": {"properties": {"path": {"type": "string"}}},
        "process.list": {"properties": {"limit": {"type": "integer"}}},
        "system.memory": {"properties": {"include_fields": {"type": "boolean"}}},
        "system.status": {"properties": {}},
    },
}

STATUS = {
    "hostname": "test-host",
    "kernel": "6.0.0",
    "architecture": "x86_64",
    "os_name": "Linux",
    "uptime_s": 3600.0,
    "load_average_1m": 0.4,
    "load_average_5m": 0.3,
    "load_average_15m": 0.2,
    "processes_running": 2,
    "processes_total": 200,
}

CPU = {
    "logical_cores": 4,
    "load_average_1m": 0.4,
    "percent": {"total": 12.5, "user": 8.0, "system": 4.5, "idle": 87.5},
}

MEMORY = {
    "total_kb": 8_000_000,
    "available_kb": 4_000_000,
    "used_kb": 4_000_000,
    "used_percent": 50.0,
    "swap_total_kb": 0,
    "swap_used_kb": 0,
}

PROCESSES = {
    "processes": [
        {"pid": 1, "name": "systemd", "state": "S", "cpu_percent": 0.1, "rss_bytes": 1024},
        {"pid": 2, "name": "kthreadd", "state": "S", "cpu_percent": None, "rss_bytes": None},
    ]
}

NETWORK = {
    "summary": {"total": 1, "by_state": {"LISTEN": 1}, "by_transport": {"tcp": 1}},
    "connections": [
        {
            "protocol": "tcp",
            "local": "127.0.0.1:8000",
            "remote": "",
            "state": "LISTEN",
            "pid": 1,
        }
    ],
}

DIAGNOSE = {
    "generated_at": "2026-11-15T10:00:00Z",
    "total_scanned": 120,
    "zombies": [
        {
            "pid": 999,
            "ppid": 1,
            "name": "defunct",
            "parent_name": "systemd",
            "reason": "zombie",
            "recommendation": "parent must reap pid 999",
        }
    ],
    "orphans": [],
    "top_cpu": [],
    "top_memory": [],
    "notes": [],
}

NETWORK_STATUS = {
    "generated_at": "2026-11-15T10:00:00Z",
    "interfaces": [],
    "default_interface": "wlp0s20f3",
    "default_gateway": "192.168.1.1",
    "notes": [],
}

HEALTH = {
    "status": "ok",
    "version": "0.7.0",
    "services": {"api": "ok", "engine": "ok", "opa": "ok", "ledger": "ok"},
}

AUDIT = [
    {
        "action_id": "act-allow",
        "action": "system.memory",
        "risk": "LOW",
        "decision": "ALLOW",
        "state": "COMPLETED",
        "denial_reason": None,
        "at": "2026-11-15T10:00:00Z",
    },
    {
        "action_id": "act-deny",
        "action": "filesystem.read",
        "risk": "MEDIUM",
        "decision": "DENY",
        "state": "DENIED",
        "denial_reason": "capability_missing",
        "at": "2026-11-15T10:01:00Z",
    },
]

SECURITY = {
    "status": "ok",
    "policy": "rego",
    "counts": {"total": 2, "allowed": 1, "denied": 1, "confirmed": 0},
    "services": {"api": "ok", "engine": "ok", "opa": "ok", "ledger": "ok"},
    "last_events": AUDIT,
}


class FakeClient:
    """The subset of CoreClient the commands and assistant use."""

    def __init__(self, **kwargs: Any) -> None:
        self.status_data = kwargs.get("status", STATUS)
        self.cpu_data = kwargs.get("cpu", CPU)
        self.memory_data = kwargs.get("memory", MEMORY)
        self.processes_data = kwargs.get("processes", PROCESSES)
        self.network_data = kwargs.get("network", NETWORK)
        self.health_data = kwargs.get("health", HEALTH)
        self.audit_entries = list(kwargs.get("audit", AUDIT))
        self.security_data = kwargs.get("security", SECURITY)
        self.verdict = kwargs.get("verdict", {"decision": "ALLOW", "data": {"ok": True}})
        self.confirm_verdict = kwargs.get("confirm_verdict")
        self.plan_payload = kwargs.get("plan_payload")
        self.apply_verdict = kwargs.get("apply_verdict")
        self.diagnose_data = kwargs.get("diagnose", DIAGNOSE)
        self.network_status_data = kwargs.get("network_status", NETWORK_STATUS)
        self.schema_data = kwargs.get("schema", SCHEMA)
        self.calls: list[tuple[str, Any]] = []

    def schema(self, *, refresh: bool = False) -> Catalog:
        return Catalog.from_schema(self.schema_data)

    def observe(self, action: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        return {
            "system.status": self.status_data,
            "system.cpu": self.cpu_data,
            "system.memory": self.memory_data,
            "process.list": self.processes_data,
            "process.diagnose": self.diagnose_data,
            "network.connections": self.network_data,
            "network.status": self.network_status_data,
        }[action]

    def status(self) -> dict[str, Any]:
        return self.status_data

    def cpu(self, interval_s: float = 0.25) -> dict[str, Any]:
        return self.cpu_data

    def memory(self, *, include_fields: bool = False) -> dict[str, Any]:
        return self.memory_data

    def processes(self, *, limit: int = 50, sort_by: str = "cpu", name_filter=None):
        return self.processes_data

    def network(self, *, limit: int = 200, listening_only: bool = False):
        return self.network_data

    def diagnose(self, *, limit: int = 200, include_orphans: bool = True, top_n: int = 5):
        return self.diagnose_data

    def network_status(self) -> dict[str, Any]:
        return self.network_status_data

    def health(self) -> dict[str, Any]:
        return self.health_data

    def audit(self, *, limit: int = 100, denied: bool = False):
        entries = [e for e in self.audit_entries if not denied or e["decision"] == "DENY"]
        return entries[:limit]

    def security_summary(self) -> dict[str, Any]:
        return self.security_data

    def propose(self, request):
        self.calls.append(("propose", request))
        return 200, dict(self.verdict)

    def confirm(self, request):
        self.calls.append(("confirm", request))
        verdict = self.confirm_verdict or {
            **self.verdict,
            "decision": "ALLOW",
            "data": {"ok": True},
        }
        return 200, dict(verdict)

    def execute(self, request, *, dry_run: bool = False):
        self.calls.append(("execute", request))
        return 200, dict(self.verdict)

    def build_plan(self, action, params, *, intent=None):
        self.calls.append(("build_plan", (action, dict(params), intent)))
        if self.plan_payload is not None:
            return {**self.plan_payload, "action": action}
        step = {
            "step_id": "step-1",
            "action": action,
            "target": str(params.get("pid") or params.get("connection")),
            "params": dict(params),
        }
        return {
            "plan_id": "plan-test",
            "plan_hash": "sha256:test",
            "kind": action,
            "action": action,
            "target": step["target"],
            "steps": [step],
            "requires_approval": True,
        }

    def apply_plan(self, plan_id, plan_hash, step_id, *, action=None):
        self.calls.append(("apply_plan", (plan_id, plan_hash, step_id, action)))
        verdict = self.apply_verdict or {
            "decision": "ALLOW",
            "executed": True,
            "target": None,
            "data": {"status": "ok"},
        }
        return 200, dict(verdict)


class FakeProvider:
    name = "fake"
    model = "fake-1"
    external = False

    def __init__(self, responses: list[str] | None = None) -> None:
        self.responses = responses or [
            '{"action": "none", "reason": "no action needed", "answer": "I can help."}'
        ]
        self.prompts: list[tuple[str, str]] = []

    def complete(self, system: str, user: str) -> str:
        self.prompts.append((system, user))
        if len(self.responses) > 1:
            return self.responses.pop(0)
        return self.responses[0]


@pytest.fixture
def fake_client() -> FakeClient:
    return FakeClient()


@pytest.fixture
def provider(monkeypatch):
    fake = FakeProvider()
    monkeypatch.setattr("aios.cli.assistant.build_provider", lambda *_args, **_kwargs: fake)
    return fake
