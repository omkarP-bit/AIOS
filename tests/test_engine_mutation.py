"""Security Engine tests for the mutation path.

A mutation must pass the same pipeline as an observation, plus a plan and an
approval that are checked in Rego and re-checked by the executor.
"""

from __future__ import annotations

import os
import shutil
from datetime import timedelta
from pathlib import Path

import pytest

from aios.actions.executor import QuarantineExecutor
from aios.actions.models import Candidate
from aios.actions.plans import ApprovalAuthority, ApprovalGrant, Plan
from aios.gateway import OSGateway
from aios.models import ActionState
from aios.models.common import utcnow
from aios.security import (
    Capability,
    CapabilityManager,
    Decision,
    DenialReason,
    InMemoryLedger,
    RegoPolicyEngine,
    RiskClass,
    SecurityEngine,
    build_policy_input,
    make_ai_request,
)

OPA = shutil.which("opa")
requires_opa = pytest.mark.skipif(
    OPA is None, reason="the packaged Rego policy needs the opa binary"
)

SECRET = b"m" * 32


def _candidate(path: Path) -> Candidate:
    st = os.lstat(path)
    return Candidate(
        candidate_id="c-engine0000000001",
        path=str(path),
        dev=st.st_dev,
        ino=st.st_ino,
        size_bytes=st.st_size,
        mtime_ns=st.st_mtime_ns,
        mode=st.st_mode,
        uid=st.st_uid,
        reason="engine test",
        tags=("log",),
    )


@pytest.fixture
def work(tmp_path: Path) -> Path:
    root = tmp_path / "work"
    root.mkdir()
    return root


@pytest.fixture
def target(work: Path) -> Path:
    path = work / "old.log"
    path.write_text("recoverable", encoding="utf-8")
    return path


@pytest.fixture
def plan(target: Path, work: Path) -> Plan:
    return Plan.from_candidates([_candidate(target)], root=str(work))


@pytest.fixture
def grant(plan: Plan) -> ApprovalGrant:
    authority = ApprovalAuthority(SECRET)
    return authority.verify(
        authority.mint(plan, approved_by="uid:1000"), plan, consume=False
    )


def _manager(*scopes: Path) -> CapabilityManager:
    return CapabilityManager(
        default_grants=[
            Capability(
                action="filesystem.quarantine",
                scope=tuple(f"{scope}/*" for scope in scopes),
                granted_by="test",
            ),
            Capability(
                action="filesystem.restore",
                scope=tuple(f"{scope}/*" for scope in scopes),
                granted_by="test",
            ),
        ]
    )


@pytest.fixture
def engine(
    proc_root: Path,
    sys_root: Path,
    tmp_path: Path,
    work: Path,
    plan: Plan,
) -> SecurityEngine:
    gateway = OSGateway(proc_root=proc_root, sys_root=sys_root)
    executor = QuarantineExecutor(tmp_path / "quarantine")
    return SecurityEngine(
        gateway,
        capability_manager=_manager(work),
        policy=RegoPolicyEngine(),
        ledger=InMemoryLedger(),
        executor=executor,
    )


def _request(plan: Plan, path: Path) -> object:
    return make_ai_request(
        "filesystem.quarantine",
        {
            "path": str(path),
            "plan_id": plan.plan_id,
            "candidate_id": plan.steps[0].candidate_id,
        },
    )


# ---------------------------------------------------------------- allow path


@requires_opa
def test_approved_plan_is_executed(
    engine: SecurityEngine, plan: Plan, grant: ApprovalGrant, target: Path
) -> None:
    verdict = engine.process(_request(plan, target), plan=plan, approval=grant)

    assert verdict.decision is Decision.ALLOW, verdict.reason
    assert verdict.state is ActionState.COMPLETED
    assert verdict.executed is True
    assert verdict.result is not None
    assert verdict.result.data["status"] == "quarantined"
    assert not target.exists()


@requires_opa
def test_approved_restore_is_executed(
    engine: SecurityEngine, plan: Plan, grant: ApprovalGrant, target: Path
) -> None:
    engine.process(_request(plan, target), plan=plan, approval=grant)
    restore = make_ai_request(
        "filesystem.restore",
        {
            "path": str(target),
            "plan_id": plan.plan_id,
            "candidate_id": plan.steps[0].candidate_id,
        },
    )
    verdict = engine.process(restore, plan=plan, approval=grant)

    assert verdict.decision is Decision.ALLOW, verdict.reason
    assert verdict.executed is True
    assert target.read_text(encoding="utf-8") == "recoverable"


@requires_opa
def test_authorize_only_does_not_move_anything(
    engine: SecurityEngine, plan: Plan, grant: ApprovalGrant, target: Path
) -> None:
    verdict = engine.authorize(_request(plan, target), plan=plan, approval=grant)

    assert verdict.decision is Decision.ALLOW
    assert verdict.executed is False
    assert target.exists()


# ---------------------------------------------------------------- deny path


@requires_opa
def test_mutation_without_a_plan_is_denied(
    engine: SecurityEngine, plan: Plan, target: Path
) -> None:
    verdict = engine.process(_request(plan, target))

    assert verdict.decision is Decision.DENY
    assert verdict.executed is False
    assert verdict.denial_reason is DenialReason.POLICY_DENY
    assert "approval" in verdict.reason
    assert target.exists()


@requires_opa
def test_approval_for_a_different_plan_is_denied(
    engine: SecurityEngine, plan: Plan, target: Path
) -> None:
    other = Plan.from_candidates(
        [_candidate(target).model_copy(update={"path": str(target)})],
        root=str(target.parent),
        intent="different plan",
    )
    authority = ApprovalAuthority(SECRET)
    other_grant = authority.verify(
        authority.mint(other, approved_by="uid:1000"), other, consume=False
    )

    verdict = engine.process(_request(plan, target), plan=plan, approval=other_grant)

    assert verdict.decision is Decision.DENY
    assert target.exists()


@requires_opa
def test_expired_approval_is_denied(
    engine: SecurityEngine, plan: Plan, grant: ApprovalGrant, target: Path
) -> None:
    expired = grant.model_copy(update={"expires_at": utcnow() - timedelta(seconds=1)})
    verdict = engine.process(_request(plan, target), plan=plan, approval=expired)

    assert verdict.decision is Decision.DENY
    assert verdict.executed is False
    assert target.exists()


@requires_opa
def test_changed_target_is_refused_after_policy_allows(
    engine: SecurityEngine, plan: Plan, grant: ApprovalGrant, target: Path
) -> None:
    target.write_text("changed after approval", encoding="utf-8")
    verdict = engine.process(_request(plan, target), plan=plan, approval=grant)

    assert verdict.decision is Decision.DENY
    assert verdict.denial_reason is DenialReason.TARGET_CHANGED
    assert verdict.executed is False
    assert target.read_text(encoding="utf-8") == "changed after approval"


@requires_opa
def test_missing_capability_is_denied_before_the_plan_is_considered(
    proc_root: Path, sys_root: Path, tmp_path: Path, plan: Plan, grant: ApprovalGrant,
    target: Path,
) -> None:
    engine = SecurityEngine(
        OSGateway(proc_root=proc_root, sys_root=sys_root),
        capability_manager=CapabilityManager(),
        policy=RegoPolicyEngine(),
        ledger=InMemoryLedger(),
        executor=QuarantineExecutor(tmp_path / "quarantine"),
    )
    verdict = engine.process(_request(plan, target), plan=plan, approval=grant)

    assert verdict.decision is Decision.DENY
    assert verdict.denial_reason in {
        DenialReason.CAPABILITY_MISSING,
        DenialReason.SCOPE_MISMATCH,
    }
    assert target.exists()


def test_mutation_is_not_served_by_the_read_only_gateway(
    proc_root: Path, sys_root: Path, plan: Plan, grant: ApprovalGrant, target: Path
) -> None:
    engine = SecurityEngine(
        OSGateway(proc_root=proc_root, sys_root=sys_root),
        capability_manager=_manager(target.parent),
        policy=RegoPolicyEngine(),
        ledger=InMemoryLedger(),
    )
    verdict = engine.process(_request(plan, target), plan=plan, approval=grant)

    assert verdict.decision is Decision.DENY
    assert verdict.denial_reason is DenialReason.NOT_IN_PROTOCOL
    assert target.exists()


# ---------------------------------------------------------------- policy doc


def test_policy_input_carries_the_catalog_and_the_plan(
    plan: Plan, grant: ApprovalGrant, target: Path
) -> None:
    document = build_policy_input(
        _request(plan, target), RiskClass.HIGH, plan=plan, approval=grant
    )

    assert document["effect"] == "STAGE"
    assert document["read_only"] is False
    assert document["approval_class"] == "plan"
    assert document["risk"] == "HIGH"
    assert document["plan"]["hash"] == plan.plan_hash
    assert document["plan"]["steps"] == 1
    assert document["approval"]["valid"] is True
    assert document["approval"]["plan_hash"] == plan.plan_hash


def test_policy_input_without_a_plan_is_empty_but_typed(target: Path) -> None:
    document = build_policy_input(
        make_ai_request("filesystem.cleanup_scan", {"path": str(target.parent)}),
        RiskClass.LOW,
    )
    assert document["plan"] == {}
    assert document["approval"] == {}
    assert document["approval_class"] == "none"
