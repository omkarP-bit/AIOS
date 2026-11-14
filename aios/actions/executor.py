"""Quarantine executor — the only component allowed to move a candidate.

The executor is deliberately small and fixed: two operations, both reversible.
It never interprets a command, never recurses, and re-checks the target
identity immediately before the rename.
"""

from __future__ import annotations

import ctypes
import json
import os
import platform
import stat as stat_module
from datetime import datetime
from pathlib import Path

from aios.actions.models import QuarantineRecord, StepResult
from aios.actions.plans import ApprovalGrant, Plan, PlanStep
from aios.models.actions import (
    ActionRequest,
    FilesystemQuarantineParams,
    FilesystemRestoreParams,
)
from aios.models.common import utcnow

_AT_FDCWD = -100
_RENAME_NOREPLACE = 1
_RENAMEAT2_SYSCALL = {"x86_64": 316, "amd64": 316, "aarch64": 276, "arm64": 276}
_libc = ctypes.CDLL(None, use_errno=True)


class ExecutorError(RuntimeError):
    def __init__(self, message: str, reason: str = "executor_refused") -> None:
        super().__init__(message)
        self.reason = reason


def _rename_noreplace(source: Path, target: Path) -> None:
    """Atomically rename without replacing an existing target."""
    src = os.fsencode(source)
    dst = os.fsencode(target)
    func = getattr(_libc, "renameat2", None)
    if func is not None:
        func.argtypes = [
            ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint
        ]
        func.restype = ctypes.c_int
        rc = func(_AT_FDCWD, src, _AT_FDCWD, dst, _RENAME_NOREPLACE)
    else:
        syscall = _RENAMEAT2_SYSCALL.get(platform.machine())
        if syscall is None:
            raise ExecutorError(
                f"renameat2 is not available on {platform.machine()}",
                "executor_unavailable",
            )
        rc = _libc.syscall(
            syscall, _AT_FDCWD, ctypes.c_char_p(src),
            _AT_FDCWD, ctypes.c_char_p(dst), _RENAME_NOREPLACE,
        )
    if rc != 0:
        err = ctypes.get_errno()
        raise OSError(err, os.strerror(err), str(target))


def _verify_identity(path: Path, step: PlanStep) -> None:
    try:
        st = os.lstat(path)
    except OSError as exc:
        raise ExecutorError(f"cannot stat {path}: {exc}", "target_missing") from exc
    if not stat_module.S_ISREG(st.st_mode):
        raise ExecutorError(f"{path} is not a regular file", "target_changed")
    actual = (st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns, st.st_mode, st.st_uid)
    expected = (
        step.dev, step.ino, step.size_bytes, step.mtime_ns, step.mode, step.uid
    )
    if actual != expected:
        raise ExecutorError(
            f"{path} changed since the plan was approved", "target_changed"
        )


def _under_root(path: Path, roots: tuple[str, ...]) -> bool:
    resolved = path.resolve()
    for root in roots:
        root_path = Path(root).resolve()
        if resolved == root_path or root_path in resolved.parents:
            return True
    return False


class QuarantineExecutor:
    """Fixed two-operation executor for filesystem quarantine and restore."""

    supported_actions = frozenset(
        {"filesystem.quarantine", "filesystem.restore"}
    )

    def __init__(self, quarantine_dir: str | Path) -> None:
        self.quarantine_dir = Path(quarantine_dir).expanduser().resolve()

    # ------------------------------------------------------------ dispatch

    def execute(
        self,
        request: ActionRequest,
        *,
        plan: Plan,
        approval: ApprovalGrant,
    ) -> StepResult:
        if approval.plan_id != plan.plan_id or approval.plan_hash != plan.plan_hash:
            raise ExecutorError("approval does not match the plan", "approval_invalid")
        if utcnow() >= approval.expires_at:
            raise ExecutorError("approval has expired", "approval_expired")
        name = request.action_name
        if name == "filesystem.quarantine":
            return self._quarantine(request, plan, approval)
        if name == "filesystem.restore":
            return self._restore(request, plan)
        raise ExecutorError(f"{name} is not a mutation action", "executor_refused")

    # ------------------------------------------------------------ quarantine

    def _quarantine(
        self,
        request: ActionRequest,
        plan: Plan,
        approval: ApprovalGrant,
    ) -> StepResult:
        params = request.typed_params
        if not isinstance(params, FilesystemQuarantineParams):
            raise ExecutorError("invalid quarantine params")
        step = self._step_for(plan, params.candidate_id, params.path)
        self._check_plan_limits(plan)

        source = Path(step.path)
        if not _under_root(source, plan.roots):
            raise ExecutorError("target is outside the approved roots", "scope_mismatch")
        if source.is_symlink():
            raise ExecutorError("symlinks are never quarantined", "target_changed")
        _verify_identity(source, step)

        base = self.quarantine_dir / plan.plan_id / step.candidate_id
        payload = base / "payload"
        meta_path = base / "meta.json"
        if base.exists():
            raise ExecutorError(
                f"quarantine slot already exists: {base}", "plan_replayed"
            )
        base.mkdir(parents=True, mode=0o700)
        try:
            if os.stat(base).st_dev != step.dev:
                raise ExecutorError(
                    "quarantine is on a different filesystem", "cross_device"
                )
            _rename_noreplace(source, payload)
        except Exception:
            base.rmdir()
            raise

        record = QuarantineRecord(
            plan_id=plan.plan_id,
            plan_hash=plan.plan_hash,
            candidate_id=step.candidate_id,
            original_path=step.path,
            dev=step.dev,
            ino=step.ino,
            size_bytes=step.size_bytes,
            mtime_ns=step.mtime_ns,
            mode=step.mode,
            uid=step.uid,
            quarantined_at=utcnow(),
            approved_by=approval.approved_by,
        )
        try:
            self._write_meta(meta_path, record)
        except Exception:
            # The move succeeded; put it back rather than leave an
            # unrecorded object in quarantine.
            _rename_noreplace(payload, source)
            base.rmdir()
            raise

        return StepResult(
            action="filesystem.quarantine",
            candidate_id=step.candidate_id,
            path=step.path,
            status="quarantined",
            quarantine_path=str(payload),
            bytes_moved=step.size_bytes,
        )

    def _write_meta(self, path: Path, record: QuarantineRecord) -> None:
        tmp = path.with_name(f".meta-{os.getpid()}.tmp")
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
        fd = os.open(tmp, flags, 0o600)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(record.model_dump(mode="json"), fh, sort_keys=True)
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp, path)
        except Exception:
            try:
                tmp.unlink()
            except OSError:
                pass
            raise

    # ------------------------------------------------------------ restore

    def _restore(self, request: ActionRequest, plan: Plan) -> StepResult:
        params = request.typed_params
        if not isinstance(params, FilesystemRestoreParams):
            raise ExecutorError("invalid restore params")
        step = self._step_for(plan, params.candidate_id, params.path)
        base = self.quarantine_dir / plan.plan_id / step.candidate_id
        payload = base / "payload"
        meta_path = base / "meta.json"
        if not meta_path.exists():
            raise ExecutorError(f"no quarantine record for {step.candidate_id}")

        record = QuarantineRecord.model_validate_json(
            meta_path.read_text(encoding="utf-8")
        )
        if record.plan_id != plan.plan_id or record.plan_hash != plan.plan_hash:
            raise ExecutorError("quarantine record does not match this plan")
        if record.original_path != step.path:
            raise ExecutorError("restore target does not match the plan")
        if not payload.exists():
            raise ExecutorError("quarantined payload is missing", "target_missing")

        st = os.lstat(payload)
        actual = (st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns, st.st_mode, st.st_uid)
        expected = (
            record.dev, record.ino, record.size_bytes, record.mtime_ns,
            record.mode, record.uid,
        )
        if actual != expected:
            raise ExecutorError("quarantined payload changed", "target_changed")

        target = Path(record.original_path)
        if not target.parent.is_dir():
            raise ExecutorError(
                f"original parent is missing: {target.parent}", "target_missing"
            )
        if target.exists() or target.is_symlink():
            raise ExecutorError(
                f"restore target already exists: {target}", "target_changed"
            )
        if os.stat(target.parent).st_dev != st.st_dev:
            raise ExecutorError("restore crosses filesystems", "cross_device")

        _rename_noreplace(payload, target)
        restored = base / f"meta.restored-{datetime.now().strftime('%Y%m%d%H%M%S')}.json"
        try:
            meta_path.rename(restored)
        except OSError:
            # The object is back in place; the sidecar remains as evidence.
            pass
        return StepResult(
            action="filesystem.restore",
            candidate_id=step.candidate_id,
            path=record.original_path,
            status="restored",
            quarantine_path=str(payload),
            bytes_moved=record.size_bytes,
        )

    # ------------------------------------------------------------ helpers

    def _step_for(self, plan: Plan, candidate_id: str, path: str) -> PlanStep:
        for step in plan.steps:
            if step.candidate_id == candidate_id:
                if step.path != path:
                    raise ExecutorError(
                        "request path does not match the approved plan",
                        "scope_mismatch",
                    )
                return step
        raise ExecutorError(
            f"{candidate_id} is not part of this plan", "scope_mismatch"
        )

    def _check_plan_limits(self, plan: Plan) -> None:
        if len(plan.steps) > plan.limits.max_items:
            raise ExecutorError("plan exceeds max_items", "limit_exceeded")
        total = sum(step.size_bytes for step in plan.steps)
        if total > plan.limits.max_bytes:
            raise ExecutorError("plan exceeds max_bytes", "limit_exceeded")


__all__ = ["ExecutorError", "QuarantineExecutor"]
