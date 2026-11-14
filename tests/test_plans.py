"""Plan hashing and approval-token tests.

A plan is approved by hash, so the hash must cover the whole body and the
token must not be reusable, transferable, or forgeable.
"""

from __future__ import annotations

from datetime import timedelta

import pytest

from aios.actions.models import Candidate
from aios.actions.plans import (
    ApprovalAuthority,
    ApprovalError,
    ApprovalGrant,
    ApprovalToken,
    Plan,
    PlanLimits,
    canonical_json,
    compute_plan_hash,
)
from aios.models.common import utcnow

SECRET = b"k" * 32


def _candidate(suffix: str = "a", *, size: int = 10) -> Candidate:
    return Candidate(
        candidate_id=f"c-{suffix:0<16}",
        path=f"/tmp/work/{suffix}.log",
        dev=44,
        ino=sum(map(ord, suffix)),
        size_bytes=size,
        mtime_ns=1_700_000_000_000_000_000,
        mode=0o100644,
        uid=1000,
        reason="log file older than 30 days",
        tags=("log",),
    )


def _plan(*candidates: Candidate, **kwargs) -> Plan:
    return Plan.from_candidates(
        candidates or (_candidate(),), root="/tmp/work", **kwargs
    )


# ---------------------------------------------------------------- hashing


def test_plan_hash_is_deterministic() -> None:
    plan = _plan(_candidate("a"), _candidate("b"))
    assert plan.plan_hash == compute_plan_hash(plan)
    assert plan.with_hash().plan_hash == plan.plan_hash


def test_plan_hash_covers_each_step() -> None:
    plan = _plan(_candidate("a"), _candidate("b"))
    changed_step = plan.steps[1].model_copy(update={"size_bytes": 11})
    changed = plan.model_copy(update={"steps": (plan.steps[0], changed_step)})
    assert compute_plan_hash(changed) != plan.plan_hash


def test_plan_hash_covers_the_roots() -> None:
    plan = _plan()
    assert compute_plan_hash(
        plan.model_copy(update={"roots": ("/tmp/other",)})
    ) != plan.plan_hash


def test_canonical_json_is_order_independent() -> None:
    assert canonical_json({"b": 1, "a": 2}) == canonical_json({"a": 2, "b": 1})


def test_plan_round_trips_through_json() -> None:
    plan = _plan(_candidate("a"))
    restored = Plan.from_dict(plan.to_dict())
    assert restored.plan_hash == plan.plan_hash
    assert restored.steps == plan.steps


def test_tampered_plan_body_is_rejected() -> None:
    plan = _plan(_candidate("a"))
    payload = plan.to_dict()
    payload["steps"][0]["path"] = "/etc/passwd"
    with pytest.raises(ValueError, match="hash"):
        Plan.from_dict(payload)


def test_tampered_plan_hash_is_rejected() -> None:
    plan = _plan(_candidate("a"))
    payload = plan.to_dict()
    payload["plan_hash"] = "sha256:" + "0" * 64
    with pytest.raises(ValueError, match="hash"):
        Plan.from_dict(payload)


def test_plan_caps_steps_at_max_items() -> None:
    plan = Plan.from_candidates(
        [_candidate("a"), _candidate("b"), _candidate("c")],
        root="/tmp/work",
        max_items=2,
    )
    assert len(plan.steps) == 2
    assert {step.action for step in plan.steps} == {"filesystem.quarantine"}
    assert {step.action for step in plan.rollback} == {"filesystem.restore"}


def test_plan_id_has_the_expected_shape() -> None:
    assert _plan().plan_id.startswith("plan-")


# ---------------------------------------------------------------- approvals


def test_minted_approval_verifies() -> None:
    plan = _plan()
    authority = ApprovalAuthority(SECRET)
    token = authority.mint(plan, approved_by="uid:1000")
    grant = authority.verify(token, plan)

    assert isinstance(grant, ApprovalGrant)
    assert grant.plan_id == plan.plan_id
    assert grant.plan_hash == plan.plan_hash
    assert grant.approved_by == "uid:1000"


def test_approval_is_bound_to_the_plan_id_and_hash() -> None:
    authority = ApprovalAuthority(SECRET)
    token = authority.mint(_plan(_candidate("a")), approved_by="uid:1000")
    other = _plan(_candidate("b"))
    with pytest.raises(ApprovalError, match="not bound"):
        authority.verify(token, other)


def test_signature_tampering_is_refused() -> None:
    plan = _plan()
    authority = ApprovalAuthority(SECRET)
    token = authority.mint(plan, approved_by="uid:1000")
    forged = token.model_copy(update={"approved_by": "nobody"})
    with pytest.raises(ApprovalError, match="signature"):
        authority.verify(forged, plan)


def test_wrong_secret_is_refused() -> None:
    plan = _plan()
    token = ApprovalAuthority(SECRET).mint(plan, approved_by="uid:1000")
    with pytest.raises(ApprovalError, match="signature"):
        ApprovalAuthority(b"z" * 32).verify(token, plan)


def test_approval_expires() -> None:
    plan = _plan()
    authority = ApprovalAuthority(SECRET, ttl_s=60)
    token = authority.mint(plan, approved_by="uid:1000")
    with pytest.raises(ApprovalError, match="expired"):
        authority.verify(token, plan, now=utcnow() + timedelta(seconds=61))


def test_approval_is_single_use() -> None:
    plan = _plan()
    authority = ApprovalAuthority(SECRET)
    token = authority.mint(plan, approved_by="uid:1000")
    authority.verify(token, plan)
    with pytest.raises(ApprovalError, match="already used"):
        authority.verify(token, plan)


def test_non_consuming_verification_allows_repeated_checks() -> None:
    plan = _plan()
    authority = ApprovalAuthority(SECRET)
    token = authority.mint(plan, approved_by="uid:1000")
    authority.verify(token, plan, consume=False)
    authority.verify(token, plan, consume=False)


def test_limits_change_invalidates_the_scope_digest() -> None:
    plan = _plan()
    authority = ApprovalAuthority(SECRET)
    token = authority.mint(plan, approved_by="uid:1000")
    wider = plan.model_copy(
        update={"limits": PlanLimits(max_items=5000, max_bytes=10**15)}
    ).with_hash()
    with pytest.raises(ApprovalError, match="(scope|bound)"):
        authority.verify(token, wider)


def test_short_secret_is_rejected() -> None:
    with pytest.raises(ValueError, match="at least 16 bytes"):
        ApprovalAuthority(b"short")


def test_token_requires_a_hashed_plan() -> None:
    plan = _plan()
    unhashed = plan.model_copy(update={"plan_hash": ""})
    with pytest.raises(ApprovalError, match="no hash"):
        ApprovalAuthority(SECRET).mint(unhashed, approved_by="uid:1000")


def test_grant_document_is_policy_shaped() -> None:
    plan = _plan()
    authority = ApprovalAuthority(SECRET)
    grant = authority.verify(
        authority.mint(plan, approved_by="uid:1000"), plan, consume=False
    )
    doc = grant.to_policy_doc()
    assert doc["valid"] is True
    assert doc["plan_hash"] == plan.plan_hash
    assert isinstance(doc["expires_at_ns"], int)


def test_token_rejects_unknown_fields() -> None:
    plan = _plan()
    token = ApprovalAuthority(SECRET).mint(plan, approved_by="uid:1000")
    payload = token.model_dump()
    payload["extra"] = True
    with pytest.raises(ValueError):
        ApprovalToken(**payload)
