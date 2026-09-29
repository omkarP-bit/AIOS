"""PostgreSQL schema for the audit trail.

Seven tables, matching the security model:

    sessions            one AI conversation
    agents              an identity that holds capabilities
    capabilities        what an agent may do, with scope and expiry
    actions             one row per proposed action (the ledger head)
    action_events       every lifecycle transition, in order
    policy_decisions    the deterministic decision and its input
    security_events     denials, violations, and anomalies

Two design points worth stating:

* The database is an *append-only* record. ``action_events`` in particular is
  never updated or deleted by the application, so the history of a decision
  cannot be rewritten after the fact.
* Nothing kernel-raw goes in here. eBPF event streams are summarised into
  ``security_events`` before they are written; the database is not a place to
  dump syscall traces.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    DateTime,
    Float,
    ForeignKey,
    Index,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    pass


class Session_(Base):
    __tablename__ = "sessions"

    session_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    agent_id: Mapped[str] = mapped_column(String(64), ForeignKey("agents.agent_id"), nullable=False)
    user_label: Mapped[str | None] = mapped_column(String(128))
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    ended_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    metadata_: Mapped[dict] = mapped_column("metadata", JSONB, default=dict)

    actions: Mapped[list[Action]] = relationship(back_populates="session")


class Agent(Base):
    __tablename__ = "agents"

    agent_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    kind: Mapped[str] = mapped_column(String(32), default="ai", nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    disabled: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    __table_args__ = (
        CheckConstraint("kind in ('ai', 'user', 'service')", name="ck_agents_kind"),
    )


class Capability_(Base):
    __tablename__ = "capabilities"

    capability_id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    agent_id: Mapped[str] = mapped_column(String(64), ForeignKey("agents.agent_id"), nullable=False)
    action: Mapped[str] = mapped_column(String(64), nullable=False)
    #: JSON array of glob patterns. Empty means unscoped.
    scope: Mapped[list] = mapped_column(JSONB, default=list, nullable=False)
    risk: Mapped[str] = mapped_column(String(16), nullable=False)
    granted_by: Mapped[str] = mapped_column(String(64), default="capability-manager")
    reason: Mapped[str | None] = mapped_column(Text)
    granted_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoked_by: Mapped[str | None] = mapped_column(String(64))

    __table_args__ = (
        Index("ix_capabilities_agent_action", "agent_id", "action"),
        # A live grant for an action is unique per agent; re-granting updates
        # the row rather than accumulating ambiguous duplicates.
        UniqueConstraint("agent_id", "action", name="uq_capabilities_agent_action"),
    )

    @property
    def is_active(self) -> bool:
        return self.revoked_at is None


class Action(Base):
    __tablename__ = "actions"

    action_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    session_id: Mapped[str | None] = mapped_column(
        String(64), ForeignKey("sessions.session_id"), index=True
    )
    agent_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    action_type: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    intent: Mapped[str | None] = mapped_column(String(256))
    target: Mapped[str | None] = mapped_column(Text)
    params: Mapped[dict] = mapped_column(JSONB, default=dict, nullable=False)
    requested_scope: Mapped[dict] = mapped_column(JSONB, default=dict, nullable=False)
    #: Trust domain the proposal arrived with. T3 for anything the model said.
    origin: Mapped[str] = mapped_column(String(8), default="T3", nullable=False)
    risk: Mapped[str] = mapped_column(String(16), nullable=False)
    state: Mapped[str] = mapped_column(String(16), nullable=False, index=True)
    decision: Mapped[str] = mapped_column(String(16), nullable=False)
    denial_reason: Mapped[str | None] = mapped_column(String(48))
    duration_ms: Mapped[float | None] = mapped_column(Float)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    session: Mapped[Session_ | None] = relationship(back_populates="actions")
    events: Mapped[list[ActionEvent]] = relationship(
        back_populates="action", cascade="all, delete-orphan"
    )
    policy_decision: Mapped[PolicyDecision_ | None] = relationship(
        back_populates="action", cascade="all, delete-orphan", uselist=False
    )

    __table_args__ = (
        Index("ix_actions_agent_created", "agent_id", "created_at"),
        CheckConstraint(
            "state in ('PROPOSED','VALIDATED','AUTHORIZED','EXECUTED','OBSERVED',"
            "'COMPLETED','DENIED','FAILED','VIOLATION')",
            name="ck_actions_state",
        ),
        CheckConstraint(
            "decision in ('ALLOW','DENY','CONFIRM')", name="ck_actions_decision"
        ),
        CheckConstraint(
            "risk in ('LOW','MEDIUM','HIGH','CRITICAL')", name="ck_actions_risk"
        ),
    )


class ActionEvent(Base):
    """Append-only lifecycle transitions. Never updated, never deleted."""

    __tablename__ = "action_events"

    event_id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    action_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("actions.action_id"), nullable=False, index=True
    )
    state: Mapped[str] = mapped_column(String(16), nullable=False)
    decision: Mapped[str] = mapped_column(String(16), nullable=False)
    risk: Mapped[str] = mapped_column(String(16), nullable=False)
    reason: Mapped[str | None] = mapped_column(Text)
    detail: Mapped[str | None] = mapped_column(Text)
    capability: Mapped[str | None] = mapped_column(Text)
    capability_reason: Mapped[str | None] = mapped_column(Text)
    target: Mapped[str | None] = mapped_column(Text)
    policy_source: Mapped[str | None] = mapped_column(String(64))
    duration_ms: Mapped[float | None] = mapped_column(Float)
    at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    action: Mapped[Action] = relationship(back_populates="events")

    __table_args__ = (
        Index("ix_action_events_action_at", "action_id", "at"),
        CheckConstraint(
            "state in ('PROPOSED','VALIDATED','AUTHORIZED','EXECUTED','OBSERVED',"
            "'COMPLETED','DENIED','FAILED','VIOLATION')",
            name="ck_action_events_state",
        ),
    )


class PolicyDecision_(Base):
    __tablename__ = "policy_decisions"

    decision_id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    action_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("actions.action_id"), nullable=False, unique=True
    )
    decision: Mapped[str] = mapped_column(String(16), nullable=False)
    risk: Mapped[str] = mapped_column(String(16), nullable=False)
    reason: Mapped[str | None] = mapped_column(Text)
    #: 'local' for v0.3, 'opa' from v0.4. Stored so an audit reader can tell
    #: which engine actually decided.
    source: Mapped[str] = mapped_column(String(32), nullable=False)
    policy_id: Mapped[str | None] = mapped_column(String(128))
    latency_ms: Mapped[float | None] = mapped_column(Float)
    #: The exact input document sent to the policy engine.
    input_doc: Mapped[dict] = mapped_column(JSONB, default=dict, nullable=False)
    decided_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    action: Mapped[Action] = relationship(back_populates="policy_decision")

    __table_args__ = (
        CheckConstraint("decision in ('ALLOW','DENY','CONFIRM')", name="ck_policy_decision"),
    )


class SecurityEvent(Base):
    """Denials, capability violations, and runtime anomalies.

    This is the table the attack-evaluation harness reads to compute a
    detection rate, so a denial that is not recorded here counts as
    undetected.
    """

    __tablename__ = "security_events"

    event_id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False, index=True
    )
    category: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    severity: Mapped[str] = mapped_column(String(16), nullable=False)
    agent_id: Mapped[str | None] = mapped_column(String(64), index=True)
    session_id: Mapped[str | None] = mapped_column(String(64), index=True)
    action_id: Mapped[str | None] = mapped_column(String(64), index=True)
    summary: Mapped[str] = mapped_column(Text, nullable=False)
    details: Mapped[dict] = mapped_column(JSONB, default=dict, nullable=False)
    acknowledged: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    __table_args__ = (
        CheckConstraint(
            "category in ('prompt_injection','capability_violation','scope_violation',"
            "'malformed_action','policy_denial','runtime_violation','anomaly')",
            name="ck_security_events_category",
        ),
        CheckConstraint("severity in ('LOW','MEDIUM','HIGH','CRITICAL')",
                        name="ck_security_events_severity"),
        Index("ix_security_events_cat_at", "category", "at"),
    )


class AuditLog(Base):
    """Who did what to the security plane itself.

    Separate from ``actions`` because these rows describe administrative
    events — capability grants and revocations — not agent behaviour.
    """

    __tablename__ = "audit_logs"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False, index=True
    )
    principal: Mapped[str] = mapped_column(String(64), nullable=False)
    operation: Mapped[str] = mapped_column(String(64), nullable=False)
    object_type: Mapped[str] = mapped_column(String(32), nullable=False)
    object_id: Mapped[str | None] = mapped_column(String(64))
    before: Mapped[dict | None] = mapped_column(JSONB)
    after: Mapped[dict | None] = mapped_column(JSONB)
    detail: Mapped[str | None] = mapped_column(Text)

    __table_args__ = (
        Index("ix_audit_logs_principal_op", "principal", "operation"),
        CheckConstraint(
            "operation in ('capability.grant','capability.revoke','agent.create',"
            "'agent.disable','session.start','session.end','policy.reload')",
            name="ck_audit_logs_operation",
        ),
    )


__all__ = [
    "Action",
    "ActionEvent",
    "Agent",
    "AuditLog",
    "Base",
    "Capability_",
    "PolicyDecision_",
    "SecurityEvent",
    "Session_",
]
