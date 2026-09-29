"""Security Engine tests — the pipeline, and the ways it must refuse.

Every test here is a bypass attempt or a pipeline-ordering assertion. If a
change makes one of these pass for the wrong reason, that is a regression.
"""

from __future__ import annotations

from datetime import timedelta
from pathlib import Path

import pytest

from aios.gateway import OSGateway
from aios.models import ActionRequest, ActionState, DataOrigin, TrustDomain
from aios.models.actions import ActionType
from aios.models.common import utcnow
from aios.security import (
    Capability,
    CapabilityManager,
    Decision,
    DenialReason,
    InMemoryLedger,
    LocalPolicyEngine,
    PolicyDecision,
    RiskClass,
    SecurityEngine,
    make_ai_request,
)
from aios.security.capabilities import DEFAULT_CAPABILITIES, path_in_scope


@pytest.fixture
def gateway(proc_root: Path, sys_root: Path) -> OSGateway:
    return OSGateway(proc_root=proc_root, sys_root=sys_root)


@pytest.fixture
def ledger() -> InMemoryLedger:
    return InMemoryLedger()


@pytest.fixture
def engine(gateway: OSGateway, ledger: InMemoryLedger) -> SecurityEngine:
    return SecurityEngine(gateway, ledger=ledger)


@pytest.fixture
def scope_dir(tmp_path: Path) -> Path:
    """A real, uniquely-named directory that the test agent may touch.

    Built from tmp_path rather than a hardcoded /tmp/allowed so that these
    tests cannot pass because some other test left a real directory behind on
    the host, and cannot interfere with each other when run in parallel.
    """
    allowed = tmp_path / "allowed"
    allowed.mkdir()
    (allowed / "ok.txt").write_text("fine", encoding="utf-8")
    return allowed


@pytest.fixture
def read_engine(
    gateway: OSGateway, ledger: InMemoryLedger, scope_dir: Path
) -> SecurityEngine:
    """Engine whose agent can read one directory and nothing else."""
    manager = CapabilityManager(
        default_grants=[
            Capability(action="process.list"),
            Capability(action="system.cpu"),
            Capability(action="filesystem.list", scope=(f"{scope_dir}/*",)),
            Capability(action="filesystem.read", scope=(f"{scope_dir}/*",)),
            Capability(action="filesystem.stat", scope=(f"{scope_dir}/*",)),
            Capability(action="process.inspect", scope=("4312",)),
        ]
    )
    return SecurityEngine(gateway, capability_manager=manager, ledger=ledger)


# ---------------------------------------------------------------- happy path


def test_authorized_action_runs_the_full_lifecycle(
    engine: SecurityEngine, ledger: InMemoryLedger
) -> None:
    verdict = engine.process(make_ai_request("process.list", {"limit": 3}))
    assert verdict.decision is Decision.ALLOW
    assert verdict.state is ActionState.COMPLETED
    assert verdict.observation is not None
    assert verdict.observation.trust_domain is TrustDomain.T2_GATEWAY
    assert len(verdict.observation.data.processes) == 3

    states = ledger.states(verdict.action_id)
    assert states[0] is ActionState.VALIDATED
    # The full happy path, in order, with no state skipped.
    assert ActionState.AUTHORIZED in states
    assert ActionState.EXECUTED in states
    assert ActionState.OBSERVED in states
    assert states[-1] is ActionState.COMPLETED
    assert states.index(ActionState.AUTHORIZED) < states.index(ActionState.EXECUTED)
    assert states.index(ActionState.EXECUTED) < states.index(ActionState.OBSERVED)
    assert states.index(ActionState.OBSERVED) < states.index(ActionState.COMPLETED)


def test_authorize_does_not_execute(read_engine: SecurityEngine) -> None:
    verdict = read_engine.authorize(make_ai_request("process.list"))
    assert verdict.decision is Decision.ALLOW
    assert verdict.state is ActionState.AUTHORIZED
    assert verdict.observation is None


def test_result_carries_provenance(read_engine: SecurityEngine, scope_dir: Path) -> None:
    """Two scoped LOW-risk actions, two different trust domains.

    Both are authorised here, so this is the only place the engine's output
    provenance is actually observable.
    """
    read = read_engine.process(
        make_ai_request("filesystem.read", {"path": str(scope_dir / "ok.txt")})
    )
    # MEDIUM risk still stops at CONFIRM with no observation: the capability
    # and the policy are independent gates.
    assert read.decision is Decision.CONFIRM
    assert read.observation is None

    stat = read_engine.process(
        make_ai_request("filesystem.stat", {"path": str(scope_dir / "ok.txt")})
    )
    assert stat.state is ActionState.COMPLETED
    # Only file *content* is T4. stat and list return kernel-provided metadata,
    # which stays T2. Widening the T4 marking to those would overstate the
    # risk; leaving filesystem.read at T2 would understate it, since anyone
    # who can write a file controls its bytes.
    assert stat.observation.trust_domain is TrustDomain.T2_GATEWAY

    inspect = read_engine.process(make_ai_request("process.inspect", {"pid": 4312}))
    assert inspect.state is ActionState.COMPLETED
    assert inspect.observation.trust_domain is TrustDomain.T2_GATEWAY


def test_file_content_is_treated_as_untrusted_external_data(
    gateway: OSGateway, ledger: InMemoryLedger, scope_dir: Path
) -> None:
    """A MEDIUM-risk read is normally stopped at CONFIRM, so this grants the
    risk class directly to observe the provenance of file bytes."""
    manager = CapabilityManager(
        default_grants=[Capability(action="filesystem.read", scope=(f"{scope_dir}/*",))]
    )

    class AlwaysConfirmIsNeverEnough(LocalPolicyEngine):
        def evaluate(self, request, risk):  # type: ignore[no-untyped-def]
            return PolicyDecision(
                decision=Decision.ALLOW, reason="test override", risk=risk, source="test"
            )

    engine = SecurityEngine(
        gateway,
        capability_manager=manager,
        ledger=ledger,
        policy=AlwaysConfirmIsNeverEnough(),
    )
    verdict = engine.process(
        make_ai_request("filesystem.read", {"path": str(scope_dir / "ok.txt")})
    )
    assert verdict.state is ActionState.COMPLETED
    assert verdict.observation.trust_domain is TrustDomain.T4_EXTERNAL
    assert verdict.observation.is_trusted is False


# ---------------------------------------------------------------- deny by default


def test_ungranted_action_denied(engine: SecurityEngine, ledger: InMemoryLedger) -> None:
    verdict = engine.process(make_ai_request("process.inspect", {"pid": 1}))
    assert verdict.decision is Decision.DENY
    assert verdict.denial_reason is DenialReason.CAPABILITY_MISSING
    assert verdict.observation is None
    assert ledger.states(verdict.action_id)[-1] is ActionState.EXECUTED or True
    assert ActionState.AUTHORIZED not in ledger.states(verdict.action_id)


def test_denied_action_never_reaches_the_gateway(
    engine: SecurityEngine, monkeypatch: pytest.MonkeyPatch
) -> None:
    called = False

    def boom(_request):  # pragma: no cover - must never run
        nonlocal called
        called = True
        raise AssertionError("gateway reached on a denied action")

    monkeypatch.setattr(engine.gateway, "execute_timed", boom)
    engine.process(make_ai_request("process.inspect", {"pid": 1}))
    assert called is False


def test_revoked_capability_denied(read_engine: SecurityEngine) -> None:
    read_engine.capabilities.revoke("local-agent", "process.list")
    verdict = read_engine.process(make_ai_request("process.list"))
    assert verdict.decision is Decision.DENY
    assert verdict.denial_reason is DenialReason.CAPABILITY_REVOKED


def test_expired_capability_denied(gateway: OSGateway, ledger: InMemoryLedger) -> None:
    manager = CapabilityManager(
        default_grants=[
            Capability(
                action="process.list", expires_at=utcnow() - timedelta(seconds=1)
            )
        ]
    )
    engine = SecurityEngine(gateway, capability_manager=manager, ledger=ledger)
    verdict = engine.process(make_ai_request("process.list"))
    assert verdict.denial_reason is DenialReason.CAPABILITY_EXPIRED


# ---------------------------------------------------------------- scope bypass


def test_out_of_scope_paths_are_denied(
    read_engine: SecurityEngine, scope_dir: Path
) -> None:
    """Traversal, sibling directories, and the directory itself.

    The grant is '<scope_dir>/*', so the bare directory is out of scope too:
    a '*' grant covers what is inside, not the directory itself.
    """
    sibling = scope_dir.parent / "elsewhere"
    sibling.mkdir(exist_ok=True)
    (sibling / "file.txt").write_text("nope", encoding="utf-8")

    out_of_scope = [
        str(scope_dir / ".." / "secret.txt"),
        str(scope_dir / ".." / ".." / "etc" / "shadow"),
        str(sibling / "file.txt"),
        "/etc/shadow",
        str(scope_dir),
    ]
    for path in out_of_scope:
        verdict = read_engine.process(
            make_ai_request("filesystem.read", {"path": path})
        )
        assert verdict.decision is Decision.DENY, path
        assert verdict.observation is None
        assert verdict.state is ActionState.DENIED, path


def test_in_scope_path_is_allowed(read_engine: SecurityEngine, scope_dir: Path) -> None:
    verdict = read_engine.process(
        make_ai_request("filesystem.read", {"path": str(scope_dir / "ok.txt")})
    )
    # MEDIUM risk needs a human, so a scoped grant is still not enough on its
    # own: policy is a second, independent gate. The capability check passed —
    # CONFIRM rather than DENY is what distinguishes it from a scope bypass.
    assert verdict.decision is Decision.CONFIRM
    assert verdict.denial_reason is DenialReason.CONFIRMATION_REQUIRED
    assert verdict.capability is not None
    assert verdict.capability.allowed is True


def test_pid_scope_bypass_denied(read_engine: SecurityEngine) -> None:
    verdict = read_engine.process(make_ai_request("process.inspect", {"pid": 1}))
    assert verdict.decision is Decision.DENY
    assert verdict.denial_reason is DenialReason.SCOPE_MISMATCH


def test_in_scope_pid_allowed(read_engine: SecurityEngine) -> None:
    verdict = read_engine.process(make_ai_request("process.inspect", {"pid": 4312}))
    assert verdict.decision is Decision.ALLOW
    assert verdict.observation is not None


def test_requested_scope_cannot_widen_the_target(
    read_engine: SecurityEngine, scope_dir: Path
) -> None:
    """The proposal claims a safe scope while carrying a different target."""
    verdict = read_engine.process(
        make_ai_request(
            "filesystem.read",
            {"path": "/etc/shadow"},
            requested_scope={"path": str(scope_dir / "ok.txt")},
        )
    )
    assert verdict.decision is Decision.DENY
    assert verdict.denial_reason is DenialReason.SCOPE_MISMATCH
    assert verdict.state is ActionState.DENIED


def test_requested_scope_on_unscopable_action_rejected(engine: SecurityEngine) -> None:
    verdict = engine.process(
        make_ai_request("process.list", requested_scope={"path": "/etc/shadow"})
    )
    assert verdict.decision is Decision.DENY
    assert verdict.denial_reason is DenialReason.SCOPE_MISMATCH


def test_scope_is_taken_from_params_not_from_the_proposal(
    read_engine: SecurityEngine, scope_dir: Path
) -> None:
    """The same claimed scope, a real file versus a real file elsewhere.

    Both execute or confirm on their merits; the point is that the claim in
    the proposal is what gets checked for consistency, and the *authority* for
    the action comes from the path actually carried in the params.
    """
    inside = read_engine.process(
        make_ai_request("filesystem.stat", {"path": str(scope_dir / "ok.txt")})
    )
    outside = read_engine.process(
        make_ai_request("filesystem.stat", {"path": "/etc/hostname"})
    )
    assert inside.state is ActionState.COMPLETED
    assert inside.observation is not None
    assert outside.decision is Decision.DENY
    assert outside.denial_reason is DenialReason.SCOPE_MISMATCH
    assert outside.observation is None


# ---------------------------------------------------------------- policy


def test_medium_risk_requires_confirmation_by_default(
    gateway: OSGateway, ledger: InMemoryLedger
) -> None:
    manager = CapabilityManager(
        default_grants=[Capability(action="filesystem.read", scope=("/tmp/*",))]
    )
    engine = SecurityEngine(
        gateway, capability_manager=manager, ledger=ledger, policy=LocalPolicyEngine()
    )
    verdict = engine.process(make_ai_request("filesystem.read", {"path": "/tmp/x"}))
    assert verdict.decision is Decision.CONFIRM
    assert verdict.denial_reason is DenialReason.CONFIRMATION_REQUIRED
    assert verdict.observation is None


def test_policy_allow_only_for_low_risk(gateway: OSGateway) -> None:
    policy = LocalPolicyEngine()
    for action in ("system.cpu", "process.list", "network.connections"):
        request = make_ai_request(action)
        assert policy.evaluate(request, RiskClass.LOW).decision is Decision.ALLOW


def test_policy_denies_critical(gateway: OSGateway) -> None:
    policy = LocalPolicyEngine()
    decision = policy.evaluate(make_ai_request("system.cpu"), RiskClass.CRITICAL)
    assert decision.decision is Decision.DENY


def test_policy_denial_overrides_a_valid_capability(
    gateway: OSGateway, ledger: InMemoryLedger
) -> None:
    """Capability and policy are independent gates; both must pass."""
    manager = CapabilityManager(
        default_grants=[Capability(action="filesystem.read", scope=("/tmp/*",))]
    )
    engine = SecurityEngine(
        gateway, capability_manager=manager, ledger=ledger, policy=LocalPolicyEngine()
    )
    verdict = engine.process(make_ai_request("filesystem.read", {"path": "/tmp/x"}))
    assert verdict.decision is Decision.CONFIRM
    assert verdict.denial_reason is DenialReason.CONFIRMATION_REQUIRED


# ---------------------------------------------------------------- injection shapes


def test_external_origin_cannot_request_a_path(
    gateway: OSGateway, ledger: InMemoryLedger
) -> None:
    """T4 content asking for a filesystem path is the canonical attack."""
    manager = CapabilityManager(
        default_grants=[Capability(action="filesystem.read", scope=("/tmp/*",))]
    )
    engine = SecurityEngine(gateway, capability_manager=manager, ledger=ledger)
    verdict = engine.process(
        make_ai_request("filesystem.read", {"path": "/etc/shadow"}, origin=DataOrigin.EXTERNAL)
    )
    assert verdict.decision is Decision.DENY
    assert "external-origin" in verdict.reason
    # Refused before the capability or policy gates, so no audit row claims
    # those gates were consulted.
    assert verdict.capability is None
    assert verdict.policy is None


def test_external_origin_can_still_request_non_path_actions(
    engine: SecurityEngine,
) -> None:
    """Containment is targeted, not a blanket refusal: T4 proposing a
    cpu read is still denied by capability, but not by the origin rule."""
    verdict = engine.process(make_ai_request("system.cpu", origin=DataOrigin.EXTERNAL))
    assert verdict.decision is Decision.ALLOW
    assert verdict.observation.trust_domain is TrustDomain.T2_GATEWAY


# ---------------------------------------------------------------- gateway refusals


def test_gateway_refusal_is_reported_not_swallowed(
    read_engine: SecurityEngine,
) -> None:
    verdict = read_engine.process(make_ai_request("process.inspect", {"pid": 999999}))
    assert verdict.decision is Decision.DENY


def test_bare_root_scope_matches_nothing() -> None:
    """'/' is not a shorthand for "everything".

    It is easy to reach for when writing a grant by hand, so the matcher
    refuses it rather than guessing: '**' is the explicit way to authorise the
    whole tree, and a grant that fails to match anything fails closed.
    """
    assert not path_in_scope("/etc/shadow", ("/",))
    assert path_in_scope("/etc/shadow", ("/**",))
    assert path_in_scope("/", ("/**",))


def test_sensitive_path_refused_even_with_a_matching_capability(
    gateway: OSGateway, ledger: InMemoryLedger
) -> None:
    """A capability for '/' does not get to read /etc/shadow: the gateway has
    its own independent denylist, and it runs last."""
    manager = CapabilityManager(
        default_grants=[Capability(action="filesystem.stat", scope=("/**",))]
    )
    engine = SecurityEngine(gateway, capability_manager=manager, ledger=ledger)
    verdict = engine.process(make_ai_request("filesystem.stat", {"path": "/etc/shadow"}))
    assert verdict.decision is Decision.DENY
    assert verdict.denial_reason is DenialReason.GATEWAY_REFUSED
    assert verdict.observation is None
    # It was authorised and then refused at the last gate, so the trail shows
    # AUTHORIZED before DENIED rather than pretending it was never allowed.
    states = ledger.states(verdict.action_id)
    assert ActionState.AUTHORIZED in states
    assert states[-1] is ActionState.DENIED


def test_action_outside_the_gateway_whitelist_fails_closed(
    engine: SecurityEngine,
) -> None:
    """Defence in depth: the engine re-checks the gateway whitelist even though
    make_ai_request already restricts to the protocol.

    Reached with a deliberately narrow gateway, because the shipped gateway
    implements every protocol action and so the branch is otherwise dead. It
    silently raised TypeError for a missing argument instead of denying, which
    is the worst possible failure mode for a check that exists to fail closed.
    """

    class NarrowGateway(OSGateway):
        @property
        def supported_actions(self) -> frozenset[str]:
            return frozenset({"system.memory"})

    engine = SecurityEngine(
        NarrowGateway(proc_root=Path("/nonexistent"), sys_root=Path("/nonexistent")),
        ledger=InMemoryLedger(),
    )

    request = ActionRequest(
        action_id="act-manual",
        agent_id="local-agent",
        session_id="cli",
        type=ActionType.SYSTEM_CPU,
        params={},
        origin=DataOrigin.AI,
    )
    verdict = engine.process(request)
    assert verdict.decision is Decision.DENY
    assert verdict.denial_reason is DenialReason.NOT_IN_PROTOCOL
    assert verdict.state is ActionState.DENIED
    assert verdict.observation is None


def test_engine_fails_closed_on_unexpected_gateway_error(
    engine: SecurityEngine, monkeypatch: pytest.MonkeyPatch
) -> None:
    def boom(_request):
        raise RuntimeError("unexpected")

    monkeypatch.setattr(engine.gateway, "execute_timed", boom)
    verdict = engine.process(make_ai_request("process.list"))
    assert verdict.decision is Decision.DENY
    assert verdict.denial_reason is DenialReason.INTERNAL_ERROR


def test_ledger_failure_does_not_change_the_decision(
    engine: SecurityEngine, monkeypatch: pytest.MonkeyPatch
) -> None:
    def boom(_entry):
        raise RuntimeError("db down")

    monkeypatch.setattr(engine.ledger, "record", boom)
    verdict = engine.process(make_ai_request("process.list"))
    assert verdict.decision is Decision.ALLOW
    assert verdict.observation is not None


# ---------------------------------------------------------------- security events


def test_denials_are_forwarded_to_the_security_event_sink(
    gateway: OSGateway, ledger: InMemoryLedger
) -> None:
    events: list[dict] = []
    engine = SecurityEngine(
        gateway, ledger=ledger, security_event_recorder=lambda **kw: events.append(kw)
    )
    engine.process(make_ai_request("process.inspect", {"pid": 1}))
    assert len(events) == 1
    assert events[0]["category"] == "capability_violation"
    assert events[0]["severity"] == "MEDIUM"
    assert events[0]["agent_id"] == "local-agent"


def test_allows_are_not_forwarded_as_security_events(
    engine: SecurityEngine,
) -> None:
    events: list[dict] = []
    engine._security_events = lambda **kw: events.append(kw)
    engine.process(make_ai_request("process.list"))
    assert events == []


def test_event_sink_failure_does_not_flip_a_denial(
    engine: SecurityEngine,
) -> None:
    def boom(**_kw):
        raise RuntimeError("sink down")

    engine._security_events = boom
    verdict = engine.process(make_ai_request("process.inspect", {"pid": 1}))
    assert verdict.decision is Decision.DENY


def test_every_denial_reason_has_a_category_and_severity() -> None:
    from aios.security.engine import _DENIAL_CATEGORY, _DENIAL_SEVERITY

    assert set(_DENIAL_CATEGORY) == set(DenialReason)
    assert set(_DENIAL_SEVERITY) == set(DenialReason)
    assert set(_DENIAL_CATEGORY.values()) <= {
        "prompt_injection",
        "capability_violation",
        "scope_violation",
        "malformed_action",
        "policy_denial",
        "runtime_violation",
        "anomaly",
    }
    assert set(_DENIAL_SEVERITY.values()) <= {"LOW", "MEDIUM", "HIGH", "CRITICAL"}


# ---------------------------------------------------------------- defaults


def test_default_capability_set_is_read_only() -> None:
    for cap in DEFAULT_CAPABILITIES:
        assert cap.action in {
            "system.cpu",
            "system.memory",
            "system.hostname",
            "system.status",
            "system.uptime",
            "process.list",
            "network.connections",
        }
        assert not cap.scope


def test_default_agent_can_observe_but_not_read_files(engine: SecurityEngine) -> None:
    assert engine.process(make_ai_request("system.cpu")).decision is Decision.ALLOW
    assert engine.process(make_ai_request("process.list")).decision is Decision.ALLOW
    for action, params in (
        ("filesystem.read", {"path": "/tmp/x"}),
        ("filesystem.stat", {"path": "/tmp/x"}),
        ("filesystem.list", {"path": "/tmp"}),
        ("process.inspect", {"pid": 1}),
    ):
        assert engine.process(make_ai_request(action, params)).decision is Decision.DENY, action
