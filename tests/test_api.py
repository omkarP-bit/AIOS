"""Control API tests.

The API is exercised through the fixture roots, so these assert the real
response shapes and the real 4xx behaviour without touching the host.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from aios.config import Settings
from aios.models import FORBIDDEN_ACTION_NAMES, PARAMS_MAP


@pytest.fixture
def client(proc_root: Path, sys_root: Path) -> TestClient:
    from aios.api import create_app

    settings = Settings(proc_root=proc_root, sys_root=sys_root, database_url="sqlite://")
    return TestClient(create_app(settings))


def test_health(client: TestClient) -> None:
    body = client.get("/health").json()
    assert body["status"] == "ok"
    from aios.actions.catalog import EXECUTOR_ACTIONS

    assert body["gateway_actions"] == len(PARAMS_MAP) - len(EXECUTOR_ACTIONS)


def test_schema_lists_allowed_and_forbidden(client: TestClient) -> None:
    body = client.get("/actions/schema").json()
    assert set(body["allowed_actions"]) == set(PARAMS_MAP)
    assert set(body["forbidden_actions"]) == set(FORBIDDEN_ACTION_NAMES)
    assert not (set(body["allowed_actions"]) & set(body["forbidden_actions"]))
    assert body["params_schema"]["process.list"]["properties"]["limit"]


def test_system_status(client: TestClient) -> None:
    body = client.get("/system/status").json()
    assert body["success"] is True
    assert body["data"]["hostname"] == "aios-fixture"
    assert body["trust_domain"] == "T2"


def test_system_memory(client: TestClient) -> None:
    body = client.get("/system/memory").json()
    assert body["data"]["total_kb"] == 16_307_636
    assert 0 < body["data"]["used_percent"] < 100


def test_system_cpu(client: TestClient) -> None:
    body = client.get("/system/cpu?interval_s=0").json()
    assert body["data"]["logical_cores"] == 2
    assert body["data"]["percent"] is not None


def test_processes_sorted_and_limited(client: TestClient) -> None:
    body = client.get("/processes?limit=3&sort_by=memory").json()
    rss = [p["rss_bytes"] for p in body["data"]["processes"]]
    assert len(rss) == 3
    assert rss == sorted(rss, reverse=True)


def test_processes_reject_bad_sort(client: TestClient) -> None:
    assert client.get("/processes?sort_by=;id").status_code == 422


def test_process_inspect_returns_hostile_cmdline_as_data(client: TestClient) -> None:
    body = client.get("/processes/7777").json()
    assert body["data"]["name"] == "evil (script)"
    assert any("rm -rf /" in arg for arg in body["data"]["cmdline"])


def test_process_inspect_missing_pid_is_403(client: TestClient) -> None:
    assert client.get("/processes/999999").status_code == 403


def test_process_inspect_rejects_bad_pid(client: TestClient) -> None:
    assert client.get("/processes/0").status_code == 422
    assert client.get("/processes/-5").status_code == 422
    assert client.get("/processes/abc").status_code == 422


def test_network_connections(client: TestClient) -> None:
    body = client.get("/network/connections?limit=10").json()
    assert body["data"]["summary"]["total"] > 0
    assert "LISTEN" in body["data"]["summary"]["by_state"]


def test_network_listening_only(client: TestClient) -> None:
    body = client.get("/network/connections?listening_only=true").json()
    assert all(c["state"] == "LISTEN" for c in body["data"]["connections"])


def test_execution_endpoint_is_the_only_agent_path(client: TestClient) -> None:
    """There is exactly one way for an agent to reach the OS, and it is the
    secured one. Replaces the v0.3 guard that no execution route existed."""
    paths = {route.path for route in client.app.routes}
    assert "/actions/execute" in paths
    assert not any(
        p.startswith("/system") and "POST" in getattr(r, "methods", set())
        for p, r in ((r.path, r) for r in client.app.routes)
    ), "the operator read routes must stay GET-only"


# ---------------------------------------------------------------- agent path


def test_agent_action_executes_through_the_engine(client: TestClient) -> None:
    body = client.post(
        "/actions/execute",
        json={
            "action_id": "act-allow-1",
            "type": "process.list",
            "params": {"limit": 2},
        },
    ).json()
    assert body["decision"] == "ALLOW"
    assert body["state"] == "COMPLETED"
    assert body["executed"] is True
    assert body["agent_id"] == "local-agent"
    assert body["risk"] == "LOW"
    assert body["data"] is not None


def test_ungranted_agent_action_is_refused_with_403(client: TestClient) -> None:
    """The default agent has no process.inspect or filesystem capability."""
    response = client.post(
        "/actions/execute",
        json={"action_id": "act-deny-1", "type": "process.inspect", "params": {"pid": 1}},
    )
    assert response.status_code == 403
    body = response.json()
    assert body["decision"] == "DENY"
    assert body["state"] == "DENIED"
    assert body["denial_reason"] == "capability_missing"
    assert body["executed"] is False
    assert body["data"] is None
    assert response.headers["X-AIOS-Reason"] == "capability_missing"


def test_dry_run_authorizes_without_executing(client: TestClient) -> None:
    body = client.post(
        "/actions/execute",
        json={
            "action_id": "act-dry-1",
            "type": "process.list",
            "params": {"limit": 1},
            "dry_run": True,
        },
    ).json()
    assert body["state"] == "AUTHORIZED"
    assert body["decision"] == "ALLOW"
    assert body["executed"] is False
    assert body["data"] is None


def test_malformed_proposal_is_rejected_before_the_engine(client: TestClient) -> None:
    """Bad input never reaches the engine, and never executes.

    Two layers, two codes: 422 is FastAPI rejecting the request body's shape
    before the handler runs, 400 is this module rejecting the action's
    meaning. The code is the incidental part; the assertion that matters is
    that nothing is executed.
    """
    body_shape = [
        {"action_id": "a4", "type": "process.list", "surprise": 1},
        {"action_id": "a5"},
    ]
    for payload in body_shape:
        assert client.post("/actions/execute", json=payload).status_code == 422, payload

    semantics = [
        {"action_id": "a1", "type": "not.a.real.action"},
        {"action_id": "a2", "type": "process.list", "params": {"limit": "many"}},
        {"action_id": "a3", "type": "process.list", "origin": "the-moon"},
    ]
    for payload in semantics:
        assert client.post("/actions/execute", json=payload).status_code == 400, payload


def test_forbidden_action_is_refused_not_executed(client: TestClient) -> None:
    response = client.post(
        "/actions/execute",
        json={"action_id": "act-forbidden", "type": "process.kill", "params": {"pid": 1}},
    )
    assert response.status_code == 400


def test_scope_bypass_is_refused(client: TestClient) -> None:
    response = client.post(
        "/actions/execute",
        json={
            "action_id": "act-scope",
            "type": "filesystem.stat",
            "params": {"path": "/etc/shadow"},
            "requested_scope": {"path": "/tmp/allowed"},
        },
    )
    assert response.status_code == 403
    assert response.json()["denial_reason"] in ("scope_mismatch", "capability_missing")


def test_health_reports_whether_the_ledger_is_durable(client: TestClient) -> None:
    body = client.get("/health").json()
    assert body["ledger"] in ("postgres", "memory")
    assert body["ledger_durable"] == (body["ledger"] == "postgres")


def test_validate_accepts_well_formed_action(client: TestClient) -> None:
    body = client.post(
        "/actions/validate",
        json={
            "action_id": "abcdefgh",
            "agent_id": "local-agent",
            "session_id": "s1",
            "type": "process.list",
            "params": {"limit": 5},
        },
    ).json()
    assert body["valid"] is True
    assert body["state"] == "VALIDATED"
    assert body["trust_domain"] == "T3"
    assert body["validated_params"]["limit"] == 5


def test_validate_denies_forbidden_action(client: TestClient) -> None:
    body = client.post(
        "/actions/validate",
        json={
            "action_id": "abcdefgh",
            "agent_id": "local-agent",
            "session_id": "s1",
            "type": "process.terminate",
            "params": {"pid": 1},
        },
    ).json()
    assert body["valid"] is False
    assert body["state"] == "DENIED"
    assert body["error"] == "forbidden_action"


def test_validate_denies_unknown_action(client: TestClient) -> None:
    """A type that is neither whitelisted nor on the denylist is unknown.

    Naming matters here: a name on the denylist is reported as forbidden,
    which tells the caller it will never be permitted. Anything else is
    reported as unknown, which is a protocol bug rather than a policy call.
    """
    body = client.post(
        "/actions/validate",
        json={
            "action_id": "abcdefgh",
            "agent_id": "local-agent",
            "session_id": "s1",
            "type": "system.telemetry_dump",
        },
    ).json()
    assert body["valid"] is False
    assert body["error"] == "unknown_action"


def test_denylisted_names_are_reported_as_forbidden(client: TestClient) -> None:
    for name in ("system.reboot", "shell.exec", "filesystem.delete"):
        body = client.post(
            "/actions/validate",
            json={
                "action_id": "abcdefgh",
                "agent_id": "local-agent",
                "session_id": "s1",
                "type": name,
            },
        ).json()
        assert body["error"] == "forbidden_action", name


def test_validate_denies_injected_param(client: TestClient) -> None:
    body = client.post(
        "/actions/validate",
        json={
            "action_id": "abcdefgh",
            "agent_id": "local-agent",
            "session_id": "s1",
            "type": "system.cpu",
            "params": {"shell": "/bin/sh", "cmd": "rm -rf /"},
        },
    ).json()
    assert body["valid"] is False
    assert "Extra inputs" in body["detail"]


def test_validate_denies_missing_fields(client: TestClient) -> None:
    body = client.post("/actions/validate", json={"type": "process.list"}).json()
    assert body["valid"] is False


def test_validate_does_not_execute(client: TestClient) -> None:
    """A valid proposal is parsed and returned, never run."""
    body = client.post(
        "/actions/validate",
        json={
            "action_id": "abcdefgh",
            "agent_id": "local-agent",
            "session_id": "s1",
            "type": "process.list",
            "params": {"limit": 1},
        },
    ).json()
    assert "data" not in body
    assert "executed" not in body


def test_read_endpoints_absent(client: TestClient) -> None:
    """filesystem.read is a gateway action, not an anonymous HTTP GET."""
    paths = {route.path for route in client.app.routes}
    assert not any("read" in p for p in paths), sorted(paths)


@pytest.mark.parametrize(
    "origin", ["kernel", "sysfs", "gateway", "security", "policy", "external", "tool"]
)
def test_agent_path_rejects_non_ai_origins(client: TestClient, origin: str) -> None:
    response = client.post(
        "/actions/execute",
        json={
            "action_id": "act-origin",
            "type": "process.list",
            "params": {"limit": 1},
            "origin": origin,
        },
    )
    assert response.status_code == 400
    assert "not accepted" in response.json()["detail"]


def test_agent_path_accepts_ai_and_user_origins(client: TestClient) -> None:
    for origin in ("ai", "user"):
        response = client.post(
            "/actions/execute",
            json={
                "action_id": f"act-origin-{origin}",
                "type": "process.list",
                "params": {"limit": 1},
                "origin": origin,
            },
        )
        assert response.status_code == 200, response.text
        assert response.json()["trust_domain"] == "T3"
