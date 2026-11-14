"""The action ledger: durable, append-only record of every decision.

:class:`PostgresLedger` implements the :class:`aios.security.engine.ActionLedger`
protocol. It is the only place in the system that writes to ``actions`` and
``action_events``.

Two invariants:

* **Every** pipeline step is written before the next one runs. A crash
  mid-execution leaves a record of exactly how far the action got, which is
  the difference between "we don't know" and "we know it was authorized but
  did not run".
* Ledger failures never change a security decision. If the database is down
  the action is still authorized or denied on the same terms; the failure is
  surfaced on the verdict, not swallowed and not turned into an allow.
"""

from __future__ import annotations

import logging
from typing import Any

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from aios.db.models import (
    Action,
    ActionEvent,
    Agent,
    AuditLog,
    Capability_,
    PolicyDecision_,
    SecurityEvent,
    Session_,
)
from aios.models import ActionState
from aios.models.common import utcnow
from aios.security.capabilities import Capability, risk_for
from aios.security.engine import LedgerRecord

log = logging.getLogger("aios.ledger")


class LedgerError(RuntimeError):
    pass


class PostgresLedger:
    """Durable implementation of the ledger protocol."""

    def __init__(self, session: Session, strict: bool = False) -> None:
        """
        :param strict: when True a write failure raises instead of being
            recorded on the verdict. Off by default: losing the audit trail
            should not change whether a read-only action runs, but it must be
            visible.
        """
        self._session = session
        self.strict = strict
        self.failures = 0
        self._logged_first_failure = False

    def _note_failure(self, message: str, exc: Exception) -> None:
        """Log a write failure without drowning the log in it.

        One action produces a dozen ledger writes, so a broken database would
        otherwise emit a dozen full tracebacks and bury the actual problem.
        The first failure is loud; the rest are counted and summarised, which
        keeps the audit gap visible without making the failure impossible to
        read.
        """
        self.failures += 1
        if self._logged_first_failure:
            log.warning("%s (failure %d suppressed)", message, self.failures)
            return
        self._logged_first_failure = True
        log.exception(message)

    # ------------------------------------------------------------ protocol

    def record(self, entry: LedgerRecord) -> None:
        """Append one audit row.

        Nothing here may raise. The invariant at the top of this module is that
        a ledger failure never changes a security decision, and that only holds
        if *every* failure mode is caught — not just the database ones. A
        programming error in here used to escape as an ``AttributeError`` and
        leave the session un-rolled-back mid-pipeline, so the scope is
        deliberately broad. Failures are counted and logged loudly; they are
        not turned into an allow.
        """
        try:
            self._write(entry)
            self._session.flush()
        except Exception as exc:
            self._note_failure(f"ledger write failed for {entry.action_id}: {exc}", exc)
            self._session.rollback()
            if self.strict:
                raise LedgerError(str(exc)) from exc

    # ------------------------------------------------------------ internals

    def _action_row(self, action_id: str) -> Action | None:
        return self._session.get(Action, action_id)

    def _write(self, entry: LedgerRecord) -> None:
        row = self._action_row(entry.action_id)
        now = entry.at or utcnow()

        if row is None:
            self._ensure_agent(entry.agent_id)
            self._ensure_session(entry.session_id, entry.agent_id)
            row = Action(
                action_id=entry.action_id,
                session_id=entry.session_id or None,
                agent_id=entry.agent_id,
                action_type=entry.action,
                risk=entry.risk.value,
                state=entry.state.value,
                decision=entry.decision.value,
                denial_reason=entry.denial_reason or entry.detail,
                target=entry.target,
                created_at=now,
                completed_at=now if entry.state in _TERMINAL else None,
            )
            self._session.add(row)
        else:
            row.state = entry.state.value
            row.decision = entry.decision.value
            if entry.denial_reason is not None:
                row.denial_reason = entry.denial_reason
            if entry.target is not None:
                row.target = entry.target
            if entry.duration_ms is not None:
                row.duration_ms = entry.duration_ms
            if entry.state in _TERMINAL:
                row.completed_at = now

        # Append-only: every step, including repeats of the same state.
        self._session.add(
            ActionEvent(
                action_id=entry.action_id,
                state=entry.state.value,
                decision=entry.decision.value,
                risk=entry.risk.value,
                reason=entry.reason,
                detail=entry.detail,
                capability=entry.capability,
                capability_reason=entry.capability_reason,
                target=entry.target,
                policy_source=entry.policy_source,
                duration_ms=entry.duration_ms,
                at=now,
            )
        )

    def _ensure_agent(self, agent_id: str) -> None:
        exists = self._session.get(Agent, agent_id)
        if exists is None:
            self._session.add(
                Agent(
                    agent_id=agent_id,
                    kind="ai",
                    description="auto-registered on first action",
                )
            )
            self._session.flush()

    def _ensure_session(self, session_id: str, agent_id: str) -> None:
        """Create the session row an action's foreign key points at.

        ``actions.session_id`` references ``sessions.session_id``, and an
        action can arrive with a session id that no ``start_session`` call ever
        registered — the CLI and the default test paths both do this. Without
        this, the insert fails the foreign key and *every* audit row for that
        action is lost, which is precisely the case where the audit trail
        matters most.

        Re-granting is harmless: the row is only added if absent, and an ended
        session that is reused is left ended rather than silently extended.
        """
        if not session_id:
            return
        if self._session.get(Session_, session_id) is None:
            self._session.add(
                Session_(
                    session_id=session_id,
                    agent_id=agent_id,
                    user_label="auto-registered on first action",
                )
            )
            self._session.flush()

    # ------------------------------------------------------------ extras

    def record_action_request(self, request: Any) -> None:
        """Persist the proposal itself, before any decision is made.

        Separate from ``record`` because the engine's ledger records decisions,
        and the request body is what an auditor needs to reconstruct *why* the
        proposal looked like that.
        """
        try:
            if self._action_row(request.action_id) is not None:
                return
            self._ensure_agent(request.agent_id)
            self._ensure_session(request.session_id, request.agent_id)
            self._session.add(
                Action(
                    action_id=request.action_id,
                    session_id=request.session_id or None,
                    agent_id=request.agent_id,
                    action_type=request.action_name,
                    intent=request.intent,
                    params=request.params,
                    requested_scope=request.requested_scope,
                    origin=request.trust_domain.value,
                    risk=risk_for(request.action_name).value,
                    state=ActionState.PROPOSED.value,
                    decision="ALLOW",
                )
            )
            self._session.flush()
        except Exception as exc:
            self._note_failure(f"failed to persist action request {request.action_id}: {exc}", exc)
            self._session.rollback()
            if self.strict:
                raise LedgerError(str(exc)) from exc

    def record_policy_decision(
        self,
        action_id: str,
        policy: Any,
        input_doc: dict[str, Any] | None = None,
        latency_ms: float | None = None,
    ) -> None:
        """Upsert the policy decision for an action."""
        try:
            if self._action_row(action_id) is None:
                return
            stmt = pg_insert(PolicyDecision_).values(
                action_id=action_id,
                decision=policy.decision.value,
                risk=policy.risk.value,
                reason=policy.reason,
                source=policy.source,
                policy_id=policy.policy_id,
                latency_ms=latency_ms,
                input_doc=input_doc or {},
            )
            stmt = stmt.on_conflict_do_update(
                index_elements=[PolicyDecision_.action_id],
                set_={
                    "decision": stmt.excluded.decision,
                    "risk": stmt.excluded.risk,
                    "reason": stmt.excluded.reason,
                    "source": stmt.excluded.source,
                    "policy_id": stmt.excluded.policy_id,
                    "latency_ms": stmt.excluded.latency_ms,
                    "input_doc": stmt.excluded.input_doc,
                    "decided_at": utcnow(),
                },
            )
            self._session.execute(stmt)
            self._session.flush()
        except Exception as exc:
            self._note_failure(f"failed to persist policy decision for {action_id}: {exc}", exc)
            self._session.rollback()
            if self.strict:
                raise LedgerError(str(exc)) from exc

    def record_security_event(
        self,
        category: str,
        severity: str,
        summary: str,
        *,
        agent_id: str | None = None,
        session_id: str | None = None,
        action_id: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> int | None:
        """Record a security event. Returns the row id, or None on failure.

        Denials must land here: the attack-evaluation harness computes a
        detection rate from this table, so a denial that fails to write is a
        denial the system cannot prove it caught.
        """
        try:
            event = SecurityEvent(
                category=category,
                severity=severity,
                summary=summary,
                agent_id=agent_id,
                session_id=session_id,
                action_id=action_id,
                details=details or {},
            )
            self._session.add(event)
            self._session.flush()
            return event.event_id
        except Exception as exc:
            self._note_failure(f"failed to persist security event: {exc}", exc)
            self._session.rollback()
            if self.strict:
                raise LedgerError(str(exc)) from exc
            return None

    def record_audit(
        self,
        principal: str,
        operation: str,
        object_type: str,
        *,
        object_id: str | None = None,
        before: dict[str, Any] | None = None,
        after: dict[str, Any] | None = None,
        detail: str | None = None,
    ) -> None:
        try:
            self._session.add(
                AuditLog(
                    principal=principal,
                    operation=operation,
                    object_type=object_type,
                    object_id=object_id,
                    before=before,
                    after=after,
                    detail=detail,
                )
            )
            self._session.flush()
        except Exception as exc:
            self._note_failure(f"failed to persist audit entry: {exc}", exc)
            self._session.rollback()
            if self.strict:
                raise LedgerError(str(exc)) from exc

    # ------------------------------------------------------------ capability sync

    def load_capabilities(self, agent_id: str) -> list[Capability]:
        """Return live grants for an agent.

        Revoked and expired rows are dropped here rather than by the caller so
        every consumer gets the same answer.
        """
        now = utcnow()
        rows = self._session.execute(
            select(Capability_).where(Capability_.agent_id == agent_id)
        ).scalars()
        grants: list[Capability] = []
        for row in rows:
            if row.revoked_at is not None:
                continue
            if row.expires_at is not None:
                expires = row.expires_at
                if expires.tzinfo is None:
                    expires = expires.replace(tzinfo=now.tzinfo)
                if expires <= now:
                    continue
            grants.append(
                Capability(
                    action=row.action,
                    scope=tuple(row.scope or ()),
                    expires_at=row.expires_at,
                    granted_by=row.granted_by,
                    reason=row.reason,
                )
            )
        return grants

    def sync_capability(
        self,
        agent_id: str,
        capability: Capability,
        *,
        principal: str = "capability-manager",
    ) -> Capability_:
        """Upsert a capability grant and write the corresponding audit row.

        Uses ON CONFLICT so a re-grant updates in place: the unique constraint
        is (agent_id, action), so there is never an ambiguous pair of live
        grants for the same action.
        """
        self._ensure_agent(agent_id)
        stmt = pg_insert(Capability_).values(
            agent_id=agent_id,
            action=capability.action,
            scope=list(capability.scope),
            risk=capability.risk if hasattr(capability, "risk") else "LOW",
            granted_by=principal,
            reason=capability.reason,
            expires_at=capability.expires_at,
            revoked_at=None,
            revoked_by=None,
        )
        stmt = stmt.on_conflict_do_update(
            constraint="uq_capabilities_agent_action",
            set_={
                "scope": stmt.excluded.scope,
                "granted_by": stmt.excluded.granted_by,
                "reason": stmt.excluded.reason,
                "expires_at": stmt.excluded.expires_at,
                "revoked_at": None,
                "revoked_by": None,
            },
        )
        self._session.execute(stmt)
        self.record_audit(
            principal,
            "capability.grant",
            "capability",
            object_id=capability.action,
            after={"agent_id": agent_id, **capability.to_dict()},
        )
        return self._session.execute(
            select(Capability_).where(
                Capability_.agent_id == agent_id,
                Capability_.action == capability.action,
            )
        ).scalar_one()

    def sync_revocation(
        self, agent_id: str, action: str, *, principal: str = "capability-manager"
    ) -> None:
        row = self._session.execute(
            select(Capability_).where(
                Capability_.agent_id == agent_id, Capability_.action == action
            )
        ).scalar_one_or_none()
        if row is None:
            return
        before = {"agent_id": agent_id, "action": action, "scope": row.scope}
        row.revoked_at = utcnow()
        row.revoked_by = principal
        self.record_audit(
            principal, "capability.revoke", "capability", object_id=action, before=before
        )

    # ------------------------------------------------------------ reads

    def get_action(self, action_id: str) -> dict[str, Any] | None:
        row = self._action_row(action_id)
        if row is None:
            return None
        events = self._session.execute(
            select(ActionEvent)
            .where(ActionEvent.action_id == action_id)
            .order_by(ActionEvent.at, ActionEvent.event_id)
        ).scalars()
        return {
            "action_id": row.action_id,
            "agent_id": row.agent_id,
            "session_id": row.session_id,
            "action_type": row.action_type,
            "state": row.state,
            "decision": row.decision,
            "risk": row.risk,
            "denial_reason": row.denial_reason,
            "target": row.target,
            "params": row.params,
            "duration_ms": row.duration_ms,
            "created_at": row.created_at,
            "completed_at": row.completed_at,
            "events": [
                {
                    "state": e.state,
                    "decision": e.decision,
                    "reason": e.reason,
                    "capability": e.capability,
                    "target": e.target,
                    "at": e.at,
                }
                for e in events
            ],
        }

    def list_actions(
        self, *, agent_id: str | None = None, limit: int = 50, state: str | None = None
    ) -> list[dict[str, Any]]:
        stmt = select(Action).order_by(Action.created_at.desc()).limit(limit)
        if agent_id:
            stmt = stmt.where(Action.agent_id == agent_id)
        if state:
            stmt = stmt.where(Action.state == state)
        rows = self._session.execute(stmt).scalars()
        return [
            {
                "action_id": r.action_id,
                "agent_id": r.agent_id,
                "action_type": r.action_type,
                "state": r.state,
                "decision": r.decision,
                "risk": r.risk,
                "denial_reason": r.denial_reason,
                "created_at": r.created_at,
            }
            for r in rows
        ]

    def list_capabilities(self, agent_id: str) -> list[dict[str, Any]]:
        rows = self._session.execute(
            select(Capability_).where(Capability_.agent_id == agent_id)
        ).scalars()
        return [
            {
                "action": c.action,
                "scope": c.scope,
                "granted_by": c.granted_by,
                "granted_at": c.granted_at,
                "expires_at": c.expires_at,
                "revoked_at": c.revoked_at,
                "revoked_by": c.revoked_by,
                "active": c.is_active,
            }
            for c in rows
        ]

    def list_security_events(
        self, *, category: str | None = None, limit: int = 50
    ) -> list[dict[str, Any]]:
        stmt = select(SecurityEvent).order_by(SecurityEvent.at.desc()).limit(limit)
        if category:
            stmt = stmt.where(SecurityEvent.category == category)
        rows = self._session.execute(stmt).scalars()
        return [
            {
                "event_id": e.event_id,
                "at": e.at,
                "category": e.category,
                "severity": e.severity,
                "agent_id": e.agent_id,
                "summary": e.summary,
                "details": e.details,
            }
            for e in rows
        ]

    def count_by_decision(self) -> dict[str, int]:
        rows = self._session.execute(
            select(Action.decision, Action.state).limit(10000)
        ).all()
        counts: dict[str, int] = {}
        for decision, _state in rows:
            counts[decision] = counts.get(decision, 0) + 1
        return counts

    def security_event_counts(self) -> dict[str, int]:
        rows = self._session.execute(
            select(SecurityEvent.category, SecurityEvent.event_id).limit(10000)
        ).all()
        counts: dict[str, int] = {}
        for category, _id in rows:
            counts[category] = counts.get(category, 0) + 1
        return counts

    def start_session(
        self, session_id: str, agent_id: str, user_label: str | None = None
    ) -> None:
        self._ensure_agent(agent_id)
        self._session.add(
            Session_(session_id=session_id, agent_id=agent_id, user_label=user_label)
        )
        self._session.flush()
        self.record_audit(
            agent_id, "session.start", "session", object_id=session_id
        )

    def end_session(self, session_id: str) -> None:
        row = self._session.get(Session_, session_id)
        if row is None:
            return
        row.ended_at = utcnow()
        self.record_audit(
            row.agent_id, "session.end", "session", object_id=session_id
        )


_TERMINAL = frozenset(
    {
        ActionState.COMPLETED,
        ActionState.DENIED,
        ActionState.FAILED,
        ActionState.VIOLATION,
    }
)


__all__ = ["LedgerError", "PostgresLedger"]
