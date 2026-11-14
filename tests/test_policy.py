"""OPA policy tests: fail-closed client, Rego policy, and audit persistence."""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import httpx
import pytest

from aios.gateway import OSGateway
from aios.models import ActionState
from aios.security import (
    Capability,
    CapabilityManager,
    Decision,
    DenialReason,
    InMemoryLedger,
    OpaPolicyEngine,
    PolicyDecision,
    RegoPolicyEngine,
    RiskClass,
    SecurityEngine,
    build_policy_input,
    make_ai_request,
)
from aios.security.capabilities import risk_for

POLICY_DIR = Path(__file__).resolve().parents[1] / "aios" / "policies"
OPA = shutil.which("opa")


@pytest.fixture
def gateway(proc_root: Path, sys_root: Path) -> OSGateway:
    return OSGateway(proc_root=proc_root, sys_root=sys_root)


class CapturingLedger(InMemoryLedger):
    def __init__(self) -> None:
        super().__init__()
        self.requests = []
        self.policies = []

    def record_action_request(self, request) -> None:  # type: ignore[no-untyped-def]
        self.requests.append(request)

    def record_policy_decision(  # type: ignore[no-untyped-def]
        self, action_id, policy, input_doc=None, latency_ms=None
    ) -> None:
        self.policies.append((action_id, policy, input_doc, latency_ms))


# ---------------------------------------------------------------- rego package


@pytest.mark.skipif(OPA is None, reason="opa binary not installed")
def test_rego_policy_suite_passes() -> None:
    result = subprocess.run(  # noqa: S603 - fixed argv, fixed binary
        [OPA, "test", str(POLICY_DIR)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "PASS" in result.stdout


@pytest.mark.skipif(OPA is None, reason="opa binary not installed")
@pytest.mark.parametrize(
    ("action", "risk", "expected"),
    [
        ("process.list", RiskClass.LOW, "ALLOW"),
        ("filesystem.read", RiskClass.MEDIUM, "CONFIRM"),
        ("system.cpu", RiskClass.CRITICAL, "DENY"),
    ],
)
def test_rego_engine_and_opa_server_agree(action: str, risk: RiskClass, expected: str) -> None:
    request = make_ai_request(action, {"path": "/tmp/x"} if "filesystem" in action else {})
    capability = Capability(action=action, scope=("/tmp/*",) if "filesystem" in action else ())
    check = CapabilityManager(default_grants=[capability]).check(
        "local-agent", action, "/tmp/x" if "filesystem" in action else None
    )

    local = RegoPolicyEngine().evaluate(request, risk, check)
    document = build_policy_input(request, risk, check)
    result = subprocess.run(  # noqa: S603 - fixed argv, fixed binary
        [
            OPA,
            "eval",
            "--format=json",
            "--stdin-input",
            "--data",
            str(POLICY_DIR),
            "data.aios.authz.decision",
        ],
        input=json.dumps(document),
        capture_output=True,
        text=True,
        check=True,
    )
    opa_decision = json.loads(result.stdout)["result"][0]["expressions"][0]["value"]["decision"]

    assert local.decision.value == expected
    assert opa_decision == expected


# ---------------------------------------------------------------- client


def _response(payload: dict, status: int = 200) -> httpx.Response:
    return httpx.Response(
        status_code=status,
        request=httpx.Request("POST", "http://opa/v1/data/aios/authz/decision"),
        json=payload,
    )


def test_opa_client_parses_allow(monkeypatch) -> None:
    monkeypatch.setattr(
        "aios.security.opa.httpx.post",
        lambda *a, **k: _response(
            {"result": {"decision": "ALLOW", "reason": "ok", "policy_id": "p"}}
        ),
    )
    request = make_ai_request("process.list")
    verdict = OpaPolicyEngine("http://opa").evaluate(request, risk_for("process.list"))
    assert verdict.decision is Decision.ALLOW
    assert verdict.source == "opa"
    assert verdict.input_doc["agent_id"] == "local-agent"
    assert verdict.latency_ms is not None and verdict.latency_ms >= 0


@pytest.mark.parametrize("exc", [httpx.ConnectError("down"), httpx.ReadTimeout("slow")])
def test_opa_client_fails_closed(monkeypatch, exc: Exception) -> None:
    def boom(*_a, **_k):
        raise exc

    monkeypatch.setattr("aios.security.opa.httpx.post", boom)
    verdict = OpaPolicyEngine("http://opa").evaluate(
        make_ai_request("process.list"), risk_for("process.list")
    )
    assert verdict.decision is Decision.DENY
    assert verdict.source == "opa:unavailable"


def test_opa_client_rejects_malformed_payload(monkeypatch) -> None:
    monkeypatch.setattr(
        "aios.security.opa.httpx.post", lambda *a, **k: _response({"result": {"decision": "MAYBE"}})
    )
    verdict = OpaPolicyEngine("http://opa").evaluate(
        make_ai_request("process.list"), risk_for("process.list")
    )
    assert verdict.decision is Decision.DENY


def test_opa_client_rejects_http_errors(monkeypatch) -> None:
    monkeypatch.setattr(
        "aios.security.opa.httpx.post", lambda *a, **k: _response({}, status=500)
    )
    verdict = OpaPolicyEngine("http://opa").evaluate(
        make_ai_request("process.list"), risk_for("process.list")
    )
    assert verdict.decision is Decision.DENY


# ---------------------------------------------------------------- engine wiring


def test_policy_inputs_and_decisions_are_persisted(gateway: OSGateway) -> None:
    ledger = CapturingLedger()
    engine = SecurityEngine(gateway, ledger=ledger)
    verdict = engine.process(make_ai_request("process.list", {"limit": 1}))

    assert verdict.state is ActionState.COMPLETED
    assert len(ledger.requests) == 1
    assert ledger.requests[0].action_name == "process.list"
    assert len(ledger.policies) == 1
    action_id, policy, input_doc, latency = ledger.policies[0]
    assert action_id == verdict.action_id
    assert policy.decision is Decision.ALLOW
    assert input_doc["action"] == "process.list"
    assert input_doc["trust_domain"] == "T3"
    assert latency is not None and latency >= 0


def test_opa_unavailable_is_a_policy_unavailable_denial(gateway: OSGateway) -> None:
    class Unavailable:
        def evaluate(self, request, risk, capability=None, *, plan=None, approval=None):  # type: ignore[no-untyped-def]
            return PolicyDecision(
                decision=Decision.DENY,
                reason="OPA unavailable: ConnectError",
                risk=risk,
                source="opa:unavailable",
            )

    ledger = CapturingLedger()
    engine = SecurityEngine(gateway, policy=Unavailable(), ledger=ledger)
    verdict = engine.process(make_ai_request("process.list"))
    assert verdict.decision is Decision.DENY
    assert verdict.denial_reason is DenialReason.POLICY_UNAVAILABLE
    assert verdict.state is ActionState.DENIED


def test_ledger_failure_does_not_change_the_decision(gateway: OSGateway) -> None:
    class BrokenLedger(InMemoryLedger):
        def record_action_request(self, request) -> None:  # type: ignore[no-untyped-def]
            raise RuntimeError("db down")

        def record_policy_decision(self, *a, **k) -> None:  # type: ignore[no-untyped-def]
            raise RuntimeError("db down")

    engine = SecurityEngine(gateway, ledger=BrokenLedger())
    verdict = engine.process(make_ai_request("process.list", {"limit": 1}))
    assert verdict.decision is Decision.ALLOW
    assert engine.ledger_errors == 2


def test_capability_scope_mismatch_is_policy_input(gateway: OSGateway) -> None:
    manager = CapabilityManager(
        default_grants=[Capability(action="filesystem.stat", scope=("/srv/allowed/*",))]
    )
    ledger = CapturingLedger()
    engine = SecurityEngine(gateway, capability_manager=manager, ledger=ledger)
    verdict = engine.process(
        make_ai_request("filesystem.stat", {"path": "/etc/passwd"})
    )
    assert verdict.decision is Decision.DENY
    assert verdict.denial_reason is DenialReason.SCOPE_MISMATCH
    # No policy decision exists: capability denied before policy ran.
    assert ledger.policies == []


def test_rego_engine_fails_closed_without_the_binary() -> None:
    request = make_ai_request("process.list")
    check = CapabilityManager().check("local-agent", "process.list", None)
    verdict = RegoPolicyEngine(binary="/nonexistent/opa").evaluate(
        request, risk_for("process.list"), check
    )
    assert verdict.decision is Decision.DENY
    assert verdict.source == "rego:unavailable"


def test_rego_engine_uses_packaged_policy_for_an_empty_directory(tmp_path: Path) -> None:
    request = make_ai_request("process.list")
    check = CapabilityManager().check("local-agent", "process.list", None)
    engine = RegoPolicyEngine(policy_dir=tmp_path / "empty")
    verdict = engine.evaluate(request, risk_for("process.list"), check)
    assert verdict.decision is Decision.ALLOW
    assert verdict.source == "rego"
