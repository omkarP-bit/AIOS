"""Data models shared by the scanner, plans, and the quarantine executor."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict


class Candidate(BaseModel):
    """One file the scanner proposes for cleanup."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    candidate_id: str
    path: str
    dev: int
    ino: int
    size_bytes: int
    mtime_ns: int
    mode: int
    uid: int
    reason: str
    tags: tuple[str, ...] = ()


class ScanResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    root: str
    candidates: tuple[Candidate, ...] = ()
    total: int = 0
    total_bytes: int = 0
    scanned_files: int = 0
    skipped: int = 0
    truncated: bool = False
    generated_at: datetime


class QuarantineRecord(BaseModel):
    """Sidecar written next to a quarantined payload."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    plan_id: str
    plan_hash: str
    candidate_id: str
    original_path: str
    dev: int
    ino: int
    size_bytes: int
    mtime_ns: int
    mode: int
    uid: int
    quarantined_at: datetime
    approved_by: str


class StepResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    action: str
    candidate_id: str
    path: str
    status: str
    detail: str | None = None
    quarantine_path: str | None = None
    bytes_moved: int = 0


class ExecutionResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    plan_id: str
    plan_hash: str
    steps: tuple[StepResult, ...] = ()
    applied: int = 0
    skipped: int = 0
    failed: int = 0
    total_bytes: int = 0


__all__ = [
    "Candidate",
    "ExecutionResult",
    "QuarantineRecord",
    "ScanResult",
    "StepResult",
]
