"""Quarantine executor tests — the only component that moves a file.

Every test here is either a successful reversible move or a refusal. Refusals
matter more: they are what stops a stale or edited plan from acting.
"""

from __future__ import annotations

import json
import os
from datetime import timedelta
from pathlib import Path

import pytest

from aios.actions.executor import ExecutorError, QuarantineExecutor
from aios.actions.models import Candidate, QuarantineRecord
from aios.actions.plans import ApprovalAuthority, ApprovalGrant, Plan, PlanLimits
from aios.models.common import utcnow
from aios.security import make_ai_request

SECRET = b"q" * 32


def _candidate(path: Path, index: int = 0) -> Candidate:
    st = os.lstat(path)
    return Candidate(
        candidate_id=f"c-test{index:012d}",
        path=str(path),
        dev=st.st_dev,
        ino=st.st_ino,
        size_bytes=st.st_size,
        mtime_ns=st.st_mtime_ns,
        mode=st.st_mode,
        uid=st.st_uid,
        reason="test fixture",
        tags=("log",),
    )


def _plan(*paths: Path, root: Path) -> Plan:
    return Plan.from_candidates(
        [_candidate(path, i) for i, path in enumerate(paths)], root=str(root)
    )


def _grant(plan: Plan) -> ApprovalGrant:
    authority = ApprovalAuthority(SECRET)
    return authority.verify(
        authority.mint(plan, approved_by="uid:1000"), plan, consume=False
    )


def _quarantine_request(plan: Plan, path: Path) -> object:
    step = next(step for step in plan.steps if step.path == str(path))
    return make_ai_request(
        "filesystem.quarantine",
        {
            "path": str(path),
            "plan_id": plan.plan_id,
            "candidate_id": step.candidate_id,
        },
    )


def _restore_request(plan: Plan, path: Path) -> object:
    step = next(step for step in plan.rollback if step.path == str(path))
    return make_ai_request(
        "filesystem.restore",
        {
            "path": str(path),
            "plan_id": plan.plan_id,
            "candidate_id": step.candidate_id,
        },
    )


@pytest.fixture
def work(tmp_path: Path) -> Path:
    root = tmp_path / "work"
    root.mkdir()
    return root


@pytest.fixture
def executor(tmp_path: Path) -> QuarantineExecutor:
    return QuarantineExecutor(tmp_path / "quarantine")


@pytest.fixture
def target(work: Path) -> Path:
    path = work / "old.log"
    path.write_text("recoverable content", encoding="utf-8")
    return path


# ---------------------------------------------------------------- quarantine


def test_quarantine_moves_the_file_and_writes_a_record(
    executor: QuarantineExecutor, work: Path, target: Path
) -> None:
    plan = _plan(target, root=work)
    grant = _grant(plan)

    result = executor.execute(
        _quarantine_request(plan, target), plan=plan, approval=grant
    )

    assert result.status == "quarantined"
    assert result.bytes_moved == len("recoverable content")
    assert not target.exists()
    payload = Path(result.quarantine_path)
    assert payload.is_file()
    assert payload.read_text(encoding="utf-8") == "recoverable content"

    meta = json.loads((payload.parent / "meta.json").read_text(encoding="utf-8"))
    record = QuarantineRecord.model_validate(meta)
    assert record.plan_id == plan.plan_id
    assert record.plan_hash == plan.plan_hash
    assert record.original_path == str(target)
    assert record.approved_by == "uid:1000"


def test_quarantine_preserves_mode_and_mtime(
    executor: QuarantineExecutor, work: Path, target: Path
) -> None:
    os.chmod(target, 0o640)
    before = os.lstat(target)
    plan = _plan(target, root=work)
    executor.execute(_quarantine_request(plan, target), plan=plan, approval=_grant(plan))
    slot = executor.quarantine_dir / plan.plan_id / plan.steps[0].candidate_id
    after = os.lstat(slot / "payload")
    assert after.st_ino == before.st_ino
    assert after.st_mode == before.st_mode
    assert after.st_mtime_ns == before.st_mtime_ns


def test_changed_target_is_refused(
    executor: QuarantineExecutor, work: Path, target: Path
) -> None:
    plan = _plan(target, root=work)
    grant = _grant(plan)
    target.write_text("edited after approval", encoding="utf-8")

    with pytest.raises(ExecutorError) as excinfo:
        executor.execute(_quarantine_request(plan, target), plan=plan, approval=grant)

    assert excinfo.value.reason == "target_changed"
    assert target.exists()
    assert "edited" in target.read_text(encoding="utf-8")


def test_deleted_target_is_refused(
    executor: QuarantineExecutor, work: Path, target: Path
) -> None:
    plan = _plan(target, root=work)
    grant = _grant(plan)
    target.unlink()

    with pytest.raises(ExecutorError) as excinfo:
        executor.execute(_quarantine_request(plan, target), plan=plan, approval=grant)
    assert excinfo.value.reason == "target_missing"


def test_symlink_is_refused(executor: QuarantineExecutor, work: Path) -> None:
    real = work / "real.log"
    real.write_text("x", encoding="utf-8")
    link = work / "link.log"
    link.symlink_to(real)
    plan = _plan(link, root=work)
    grant = _grant(plan)

    with pytest.raises(ExecutorError) as excinfo:
        executor.execute(_quarantine_request(plan, link), plan=plan, approval=grant)
    assert excinfo.value.reason == "target_changed"
    assert link.is_symlink() and real.exists()


def test_path_that_differs_from_the_plan_is_refused(
    executor: QuarantineExecutor, work: Path, target: Path
) -> None:
    other = work / "other.log"
    other.write_text("x", encoding="utf-8")
    plan = _plan(target, root=work)
    grant = _grant(plan)
    request = _quarantine_request(plan, target)
    object.__setattr__(request, "params", {**request.params, "path": str(other)})

    with pytest.raises(ExecutorError) as excinfo:
        executor.execute(request, plan=plan, approval=grant)
    assert excinfo.value.reason == "scope_mismatch"
    assert other.exists()


def test_candidate_outside_the_plan_is_refused(
    executor: QuarantineExecutor, work: Path, target: Path
) -> None:
    plan = _plan(target, root=work)
    grant = _grant(plan)
    request = make_ai_request(
        "filesystem.quarantine",
        {
            "path": str(target),
            "plan_id": plan.plan_id,
            "candidate_id": "c-notinthisplan",
        },
    )
    with pytest.raises(ExecutorError) as excinfo:
        executor.execute(request, plan=plan, approval=grant)
    assert excinfo.value.reason == "scope_mismatch"


def test_target_outside_the_approved_root_is_refused(
    executor: QuarantineExecutor, work: Path, target: Path, tmp_path: Path
) -> None:
    outside = tmp_path / "outside.log"
    outside.write_text("x", encoding="utf-8")
    plan = _plan(target, root=work)
    forged = plan.model_copy(
        update={
            "steps": (
                plan.steps[0].model_copy(update={"path": str(outside)}),
            )
        }
    ).with_hash()
    request = make_ai_request(
        "filesystem.quarantine",
        {
            "path": str(outside),
            "plan_id": forged.plan_id,
            "candidate_id": forged.steps[0].candidate_id,
        },
    )
    with pytest.raises(ExecutorError) as excinfo:
        executor.execute(request, plan=forged, approval=_grant(forged))
    assert excinfo.value.reason == "scope_mismatch"
    assert outside.exists()


def test_replayed_plan_slot_is_refused(
    executor: QuarantineExecutor, work: Path, target: Path
) -> None:
    plan = _plan(target, root=work)
    grant = _grant(plan)
    slot = Path(executor.quarantine_dir) / plan.plan_id / plan.steps[0].candidate_id
    slot.mkdir(parents=True)

    with pytest.raises(ExecutorError) as excinfo:
        executor.execute(_quarantine_request(plan, target), plan=plan, approval=grant)
    assert excinfo.value.reason == "plan_replayed"
    assert target.exists()


def test_plan_limits_are_enforced(
    executor: QuarantineExecutor, work: Path, target: Path
) -> None:
    second = work / "second.log"
    second.write_text("y", encoding="utf-8")
    plan = _plan(target, second, root=work)
    tight = plan.model_copy(
        update={
            "limits": PlanLimits(
                max_items=1, max_bytes=sum(step.size_bytes for step in plan.steps)
            )
        }
    ).with_hash()
    with pytest.raises(ExecutorError) as excinfo:
        executor.execute(
            _quarantine_request(tight, target), plan=tight, approval=_grant(tight)
        )
    assert excinfo.value.reason == "limit_exceeded"
    assert target.exists()


def test_expired_approval_is_refused(
    executor: QuarantineExecutor, work: Path, target: Path
) -> None:
    plan = _plan(target, root=work)
    grant = _grant(plan).model_copy(
        update={"expires_at": utcnow() - timedelta(seconds=1)}
    )
    with pytest.raises(ExecutorError) as excinfo:
        executor.execute(_quarantine_request(plan, target), plan=plan, approval=grant)
    assert excinfo.value.reason == "approval_expired"
    assert target.exists()


def test_approval_for_another_plan_is_refused(
    executor: QuarantineExecutor, work: Path, target: Path
) -> None:
    plan = _plan(target, root=work)
    other = _plan(target, root=work)
    with pytest.raises(ExecutorError) as excinfo:
        executor.execute(
            _quarantine_request(plan, target), plan=plan, approval=_grant(other)
        )
    assert excinfo.value.reason == "approval_invalid"
    assert target.exists()


def test_non_mutation_action_is_refused(
    executor: QuarantineExecutor, work: Path, target: Path
) -> None:
    plan = _plan(target, root=work)
    request = make_ai_request("filesystem.read", {"path": str(target)})
    with pytest.raises(ExecutorError) as excinfo:
        executor.execute(request, plan=plan, approval=_grant(plan))
    assert excinfo.value.reason == "executor_refused"


def test_cross_device_quarantine_is_refused(work: Path, target: Path, tmp_path: Path) -> None:
    other_device = Path("/dev/shm")
    if not other_device.is_dir() or os.stat(other_device).st_dev == os.stat(target).st_dev:
        pytest.skip("no second filesystem available for this test")
    executor = QuarantineExecutor(other_device / f"aios-test-{os.getpid()}-{tmp_path.name}")
    plan = _plan(target, root=work)
    try:
        with pytest.raises(ExecutorError) as excinfo:
            executor.execute(
                _quarantine_request(plan, target), plan=plan, approval=_grant(plan)
            )
        assert excinfo.value.reason == "cross_device"
    finally:
        slot = executor.quarantine_dir / plan.plan_id
        if slot.exists():
            slot.rmdir()
        if executor.quarantine_dir.exists():
            executor.quarantine_dir.rmdir()


# ---------------------------------------------------------------- restore


def test_restore_returns_the_original_file(
    executor: QuarantineExecutor, work: Path, target: Path
) -> None:
    original_mode = 0o100640
    os.chmod(target, 0o640)
    before = os.lstat(target)
    plan = _plan(target, root=work)
    grant = _grant(plan)
    executor.execute(_quarantine_request(plan, target), plan=plan, approval=grant)
    assert not target.exists()

    result = executor.execute(_restore_request(plan, target), plan=plan, approval=grant)

    assert result.status == "restored"
    assert target.read_text(encoding="utf-8") == "recoverable content"
    after = os.lstat(target)
    assert after.st_ino == before.st_ino
    assert after.st_mode == original_mode
    assert after.st_mtime_ns == before.st_mtime_ns


def test_restore_refuses_when_the_original_path_is_occupied(
    executor: QuarantineExecutor, work: Path, target: Path
) -> None:
    plan = _plan(target, root=work)
    grant = _grant(plan)
    executor.execute(_quarantine_request(plan, target), plan=plan, approval=grant)
    target.write_text("someone else", encoding="utf-8")

    with pytest.raises(ExecutorError) as excinfo:
        executor.execute(_restore_request(plan, target), plan=plan, approval=grant)
    assert excinfo.value.reason == "target_changed"
    assert target.read_text(encoding="utf-8") == "someone else"


def test_restore_without_a_record_is_refused(
    executor: QuarantineExecutor, work: Path, target: Path
) -> None:
    plan = _plan(target, root=work)
    with pytest.raises(ExecutorError, match="no quarantine record"):
        executor.execute(_restore_request(plan, target), plan=plan, approval=_grant(plan))


def test_restore_after_changed_payload_is_refused(
    executor: QuarantineExecutor, work: Path, target: Path
) -> None:
    plan = _plan(target, root=work)
    grant = _grant(plan)
    result = executor.execute(
        _quarantine_request(plan, target), plan=plan, approval=grant
    )
    Path(result.quarantine_path).write_text("tampered", encoding="utf-8")

    with pytest.raises(ExecutorError) as excinfo:
        executor.execute(_restore_request(plan, target), plan=plan, approval=grant)
    assert excinfo.value.reason == "target_changed"
    assert not target.exists()


def test_restore_requires_the_matching_plan(
    executor: QuarantineExecutor, work: Path, target: Path
) -> None:
    plan = _plan(target, root=work)
    other = _plan(target, root=work)
    grant = _grant(plan)
    executor.execute(_quarantine_request(plan, target), plan=plan, approval=grant)
    with pytest.raises(ExecutorError):
        executor.execute(_restore_request(other, target), plan=other, approval=_grant(other))
