"""Client tests: response-shape validation and friendly error mapping.

Every test here goes through httpx.MockTransport, so no socket is opened and
the CLI never touches the real core.
"""

from __future__ import annotations

import httpx
import pytest

from aios.ai.protocol import ActionRequest
from aios.cli.client import CoreClient
from aios.cli.errors import (
    EXIT_UNAVAILABLE,
    CliError,
    ServiceUnavailable,
    unexpected_response,
)

BASE = "http://127.0.0.1:8000"


def client_with(handler) -> CoreClient:
    return CoreClient(BASE, timeout_s=1.0, transport=httpx.MockTransport(handler))


def request() -> ActionRequest:
    return ActionRequest(
        action_id="act-test",
        agent_id="local-agent",
        session_id="test",
        type="system.memory",
        params={},
    )


def test_unreachable_core_is_exit_4() -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused", request=_request)

    with pytest.raises(ServiceUnavailable) as caught:
        client_with(handler).health()
    assert caught.value.exit_code == EXIT_UNAVAILABLE
    assert "Cannot reach the AIOS core" in caught.value.message
    assert "aios-core serve" in (caught.value.next_step or "")


def test_timeout_is_exit_4() -> None:
    def handler(transport_request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("slow", request=transport_request)

    with pytest.raises(ServiceUnavailable) as caught:
        client_with(handler).status()
    assert caught.value.exit_code == EXIT_UNAVAILABLE
    assert "did not answer" in caught.value.message


def test_server_error_is_exit_4() -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(500, json={"detail": "ledger is full"})

    with pytest.raises(ServiceUnavailable) as caught:
        client_with(handler).health()
    assert caught.value.exit_code == EXIT_UNAVAILABLE
    assert "ledger is full" in caught.value.message


def test_non_json_body_is_reported() -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="<html>not the core</html>")

    with pytest.raises(ServiceUnavailable) as caught:
        client_with(handler).health()
    assert caught.value.exit_code == EXIT_UNAVAILABLE
    assert "unexpected response" in caught.value.message


def test_missing_route_means_a_stale_core() -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(404, text="404 page not found")

    with pytest.raises(ServiceUnavailable) as caught:
        client_with(handler).propose(request())
    assert caught.value.exit_code == EXIT_UNAVAILABLE
    assert "older than this client" in caught.value.message
    assert "make up" in (caught.value.next_step or "")


def test_health_requires_services() -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"status": "ok", "version": "0.7.0"})

    with pytest.raises(ServiceUnavailable):
        client_with(handler).health()


def test_audit_requires_a_list() -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"entries": None})

    with pytest.raises(ServiceUnavailable):
        client_with(handler).audit()


def test_observation_requires_data_object() -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"data": ["not", "an", "object"]})

    with pytest.raises(ServiceUnavailable):
        client_with(handler).status()


def test_deny_verdict_is_returned_not_raised() -> None:
    body = {
        "action_id": "act-test",
        "decision": "DENY",
        "risk": "HIGH",
        "denial_reason": "forbidden_action",
        "target": "/etc/shadow",
    }

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(403, json=body, headers={"X-AIOS-Reason": "forbidden_action"})

    status, verdict = client_with(handler).propose(request())
    assert status == 403
    assert verdict["decision"] == "DENY"
    assert verdict["denial_reason"] == "forbidden_action"


def test_confirm_verdict_is_returned() -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"decision": "ALLOW", "executed": True})

    status, verdict = client_with(handler).confirm(request())
    assert status == 200
    assert verdict["executed"] is True


def test_verdict_must_have_a_known_decision() -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"decision": "MAYBE"})

    with pytest.raises(ServiceUnavailable):
        client_with(handler).propose(request())


def test_plain_http_error_is_general_error() -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(400, json={"detail": "bad action"})

    with pytest.raises(CliError) as caught:
        client_with(handler).propose(request())
    assert caught.value.exit_code == 1
    assert "bad action" in caught.value.message


def test_unexpected_response_helper_is_exit_4() -> None:
    assert unexpected_response("/health").exit_code == EXIT_UNAVAILABLE


def test_build_plan_posts_intent_and_requires_core_ids() -> None:
    seen: dict[str, object] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["path"] = request.url.path
        seen["body"] = request.content.decode()
        return httpx.Response(
            200,
            json={
                "plan_id": "plan-core",
                "plan_hash": "sha256:core",
                "steps": [{"step_id": "step-1", "action": "process.signal"}],
            },
        )

    body = client_with(handler).build_plan(
        "process.signal", {"pid": 42, "signal": "TERM"}, intent="stop it"
    )
    assert body["plan_hash"] == "sha256:core"
    assert seen["path"] == "/actions/plan"
    assert '"pid":42' in str(seen["body"])
    assert '"signal":"TERM"' in str(seen["body"])


def test_build_plan_rejects_a_response_without_a_hash() -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"plan_id": "plan-core", "steps": []})

    with pytest.raises(ServiceUnavailable):
        client_with(handler).build_plan("process.signal", {"pid": 42, "signal": "TERM"})


def test_apply_plan_sends_the_exact_hash() -> None:
    seen: dict[str, object] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["path"] = request.url.path
        seen["body"] = request.content.decode()
        return httpx.Response(200, json={"decision": "ALLOW", "executed": True})

    status, verdict = client_with(handler).apply_plan(
        "plan-core", "sha256:core", "step-1", action="process.signal"
    )
    assert status == 200
    assert verdict["executed"] is True
    assert seen["path"] == "/actions/apply"
    assert "sha256:core" in str(seen["body"])


def test_plan_refusal_keeps_the_core_detail() -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            409,
            json={
                "error": "zombie_not_killable",
                "detail": "a zombie is already dead; its parent must reap it",
            },
        )

    with pytest.raises(CliError) as caught:
        client_with(handler).build_plan("process.signal", {"pid": 42, "signal": "KILL"})
    assert "parent must reap" in caught.value.message
