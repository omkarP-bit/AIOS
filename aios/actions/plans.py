"""Immutable cleanup plans and operator approval tokens.

The plan hash is computed by this module, never accepted from the planner.
Approval is an HMAC over the plan-bound token, issued only after an operator
has confirmed the plan hash.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import uuid
from datetime import datetime, timedelta
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from aios.actions.catalog import CATALOG_VERSION, FORBIDDEN_ACTIONS
from aios.actions.models import Candidate
from aios.models.common import utcnow


class PlanLimits(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    max_items: int = Field(ge=1, le=5000)
    max_bytes: int = Field(ge=0)


class PlanStep(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    step_id: str
    action: str
    candidate_id: str
    path: str
    dev: int
    ino: int
    size_bytes: int
    mtime_ns: int
    mode: int
    uid: int


class RollbackStep(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    step_id: str
    action: str
    candidate_id: str
    path: str


class Plan(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    plan_id: str
    catalog_version: str = CATALOG_VERSION
    agent_id: str
    session_id: str
    intent: str | None = None
    created_at: datetime = Field(default_factory=utcnow)
    roots: tuple[str, ...]
    limits: PlanLimits
    steps: tuple[PlanStep, ...]
    rollback: tuple[RollbackStep, ...] = ()
    plan_hash: str = ""

    @classmethod
    def from_candidates(
        cls,
        candidates: list[Candidate] | tuple[Candidate, ...],
        *,
        root: str,
        agent_id: str = "local-agent",
        session_id: str = "cli",
        intent: str | None = None,
        max_items: int = 500,
        max_bytes: int = 10_737_418_240,
    ) -> Plan:
        chosen = tuple(candidates[:max_items])
        steps = tuple(
            PlanStep(
                step_id=f"step-{index}",
                action="filesystem.quarantine",
                candidate_id=c.candidate_id,
                path=c.path,
                dev=c.dev,
                ino=c.ino,
                size_bytes=c.size_bytes,
                mtime_ns=c.mtime_ns,
                mode=c.mode,
                uid=c.uid,
            )
            for index, c in enumerate(chosen, start=1)
        )
        rollback = tuple(
            RollbackStep(
                step_id=step.step_id,
                action="filesystem.restore",
                candidate_id=step.candidate_id,
                path=step.path,
            )
            for step in steps
        )
        plan = cls(
            plan_id="plan-" + uuid.uuid4().hex[:24],
            agent_id=agent_id,
            session_id=session_id,
            intent=intent,
            roots=(str(root),),
            limits=PlanLimits(max_items=max_items, max_bytes=max_bytes),
            steps=steps,
            rollback=rollback,
        )
        return plan.with_hash()

    def with_hash(self) -> Plan:
        return self.model_copy(update={"plan_hash": compute_plan_hash(self)})

    def to_policy_doc(self) -> dict[str, Any]:
        total_bytes = sum(step.size_bytes for step in self.steps)
        return {
            "id": self.plan_id,
            "hash": self.plan_hash,
            "steps": len(self.steps),
            "forbidden_step": any(
                step.action in FORBIDDEN_ACTIONS for step in self.steps
            ),
            "limits": {
                "items_ok": len(self.steps) <= self.limits.max_items,
                "bytes_ok": total_bytes <= self.limits.max_bytes,
            },
        }

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json")

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> Plan:
        plan = cls.model_validate(payload)
        if plan.plan_hash != compute_plan_hash(plan):
            raise ValueError("plan hash does not match the plan body")
        return plan


def canonical_json(payload: Any) -> bytes:
    return json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def compute_plan_hash(plan: Plan) -> str:
    body = plan.model_dump(mode="json", exclude={"plan_hash"})
    material = canonical_json(body) + canonical_json(
        {"catalog_version": plan.catalog_version}
    )
    return "sha256:" + hashlib.sha256(material).hexdigest()


class ApprovalToken(BaseModel):
    """Signed operator approval. Signature covers every other field."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    token_version: int = 1
    plan_id: str
    plan_hash: str
    approved_by: str
    approved_at: datetime
    expires_at: datetime
    nonce: str
    scope_digest: str
    signature: str = ""


class ApprovalGrant(BaseModel):
    """A token that has been verified against a specific plan."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    plan_id: str
    plan_hash: str
    approved_by: str
    approved_at: datetime
    expires_at: datetime
    nonce: str
    scope_digest: str

    def to_policy_doc(self) -> dict[str, Any]:
        return {
            "valid": True,
            "plan_id": self.plan_id,
            "plan_hash": self.plan_hash,
            "approved_by": self.approved_by,
            "expires_at_ns": int(self.expires_at.timestamp() * 1_000_000_000),
            "nonce": self.nonce,
        }


class ApprovalError(RuntimeError):
    pass


def _scope_digest(plan: Plan) -> str:
    material = canonical_json(
        {"roots": list(plan.roots), "limits": plan.limits.model_dump(mode="json")}
    )
    return "sha256:" + hashlib.sha256(material).hexdigest()


class ApprovalAuthority:
    """Mints and verifies short-lived, single-use plan approvals."""

    def __init__(self, secret: bytes, *, ttl_s: int = 900) -> None:
        if len(secret) < 16:
            raise ValueError("approval secret must be at least 16 bytes")
        self._secret = secret
        self.ttl_s = ttl_s
        self._used_nonces: set[str] = set()

    def _signature(self, payload: dict[str, Any]) -> str:
        return hmac.new(self._secret, canonical_json(payload), hashlib.sha256).hexdigest()

    def mint(
        self,
        plan: Plan,
        *,
        approved_by: str,
        ttl_s: int | None = None,
    ) -> ApprovalToken:
        if not plan.plan_hash:
            raise ApprovalError("plan has no hash")
        now = utcnow()
        body = {
            "token_version": 1,
            "plan_id": plan.plan_id,
            "plan_hash": plan.plan_hash,
            "approved_by": approved_by,
            "approved_at": now,
            "expires_at": now + timedelta(seconds=ttl_s or self.ttl_s),
            "nonce": secrets.token_urlsafe(24),
            "scope_digest": _scope_digest(plan),
        }
        # Sign the canonical *token* serialisation, not the input dict: the two
        # differ in datetime formatting, and verification re-serialises.
        unsigned = ApprovalToken(**body, signature="")
        payload = unsigned.model_dump(mode="json", exclude={"signature"})
        return unsigned.model_copy(update={"signature": self._signature(payload)})

    def verify(
        self,
        token: ApprovalToken,
        plan: Plan,
        *,
        consume: bool = True,
        now: datetime | None = None,
    ) -> ApprovalGrant:
        now = now or utcnow()
        body = token.model_dump(mode="json", exclude={"signature"})
        expected = self._signature(body)
        if not hmac.compare_digest(expected, token.signature):
            raise ApprovalError("approval signature is invalid")
        if token.plan_id != plan.plan_id or token.plan_hash != plan.plan_hash:
            raise ApprovalError("approval is not bound to this plan")
        if token.scope_digest != _scope_digest(plan):
            raise ApprovalError("approval scope does not match this plan")
        if now >= token.expires_at:
            raise ApprovalError("approval has expired")
        if consume:
            if token.nonce in self._used_nonces:
                raise ApprovalError("approval token was already used")
            self._used_nonces.add(token.nonce)
        return ApprovalGrant(
            plan_id=token.plan_id,
            plan_hash=token.plan_hash,
            approved_by=token.approved_by,
            approved_at=token.approved_at,
            expires_at=token.expires_at,
            nonce=token.nonce,
            scope_digest=token.scope_digest,
        )


__all__ = [
    "ApprovalAuthority",
    "ApprovalError",
    "ApprovalGrant",
    "ApprovalToken",
    "Plan",
    "PlanLimits",
    "PlanStep",
    "RollbackStep",
    "canonical_json",
    "compute_plan_hash",
]
