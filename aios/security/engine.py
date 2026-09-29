"""The Security Engine.

This is the component the whole design rests on. Its contract:

    The AI proposes. The Security Engine decides. Nothing else may execute.

Concretely, an action reaches the OS Gateway only by passing, in order:

  1. **Protocol validation** — strict schema, closed action enum, no extras.
  2. **Structural checks** — the target named in the action must be the one
     the params actually carry. A proposal that says "inspect 1" while
     carrying ``pid=4312`` is rejected rather than resolved in the AI's favour.
  3. **Risk classification** — from a fixed table, never from model output.
  4. **Capability check** — exact-action grant, scope-checked, deny by default.
  5. **Policy decision** — local policy in v0.3, OPA from v0.4. Absent OPA the
     engine runs in local mode and *still* fails closed for anything above
     the configured ceiling.

The engine is the only caller of ``OSGateway.execute`` outside the read-only
CLI observation path, and it always logs before and after.
"""

from __future__ import annotations

import logging
import time
import uuid
from collections.abc import Callable
from datetime import datetime
from enum import Enum
from typing import Any, Protocol

from pydantic import BaseModel, ConfigDict, Field

from aios.gateway import ActionNotPermitted, GatewayError, OSGateway, PreconditionFailed
from aios.models import (
    FORBIDDEN_ACTION_NAMES,
    ActionRequest,
    ActionResult,
    ActionState,
    DataOrigin,
    assert_transition,
)
from aios.models.common import Observation, TrustDomain, utcnow
from aios.security.capabilities import (
    PATH_PARAM_ACTIONS,
    RiskClass,
    ScopeDimension,
    _normalise,
    risk_for,
    scope_dimension_for,
)
from aios.security.manager import CapabilityCheck, CapabilityManager


class Decision(str, Enum):
    ALLOW = "ALLOW"
    CONFIRM = "CONFIRM"
    DENY = "DENY"


log = logging.getLogger("aios.security")


#: Why an action was rejected. Kept as a closed enum so the reason can be
#: counted in the audit table without parsing free text.
class DenialReason(str, Enum):
    NOT_IN_PROTOCOL = "not_in_protocol"
    FORBIDDEN_ACTION = "forbidden_action"
    INVALID_PARAMS = "invalid_params"
    SCOPE_MISMATCH = "scope_mismatch"
    CAPABILITY_MISSING = "capability_missing"
    CAPABILITY_REVOKED = "capability_revoked"
    CAPABILITY_EXPIRED = "capability_expired"
    RISK_TOO_HIGH = "risk_too_high"
    POLICY_DENY = "policy_deny"
    POLICY_UNAVAILABLE = "policy_unavailable"
    GATEWAY_REFUSED = "gateway_refused"
    GATEWAY_ERROR = "gateway_error"
    CONFIRMATION_REQUIRED = "confirmation_required"
    INTERNAL_ERROR = "internal_error"


#: Denial -> security_events.category. Every denial must map to a category or
#: it will not appear in the detection-rate measurement.
_DENIAL_CATEGORY: dict[DenialReason, str] = {
    DenialReason.NOT_IN_PROTOCOL: "malformed_action",
    DenialReason.FORBIDDEN_ACTION: "policy_denial",
    DenialReason.INVALID_PARAMS: "malformed_action",
    DenialReason.SCOPE_MISMATCH: "scope_violation",
    DenialReason.CAPABILITY_MISSING: "capability_violation",
    DenialReason.CAPABILITY_REVOKED: "capability_violation",
    DenialReason.CAPABILITY_EXPIRED: "capability_violation",
    DenialReason.RISK_TOO_HIGH: "policy_denial",
    DenialReason.POLICY_DENY: "policy_denial",
    DenialReason.POLICY_UNAVAILABLE: "policy_denial",
    DenialReason.GATEWAY_REFUSED: "policy_denial",
    DenialReason.GATEWAY_ERROR: "anomaly",
    DenialReason.CONFIRMATION_REQUIRED: "policy_denial",
    DenialReason.INTERNAL_ERROR: "anomaly",
}

_DENIAL_SEVERITY: dict[DenialReason, str] = {
    DenialReason.NOT_IN_PROTOCOL: "LOW",
    DenialReason.FORBIDDEN_ACTION: "HIGH",
    DenialReason.INVALID_PARAMS: "LOW",
    DenialReason.SCOPE_MISMATCH: "HIGH",
    DenialReason.CAPABILITY_MISSING: "MEDIUM",
    DenialReason.CAPABILITY_REVOKED: "HIGH",
    DenialReason.CAPABILITY_EXPIRED: "LOW",
    DenialReason.RISK_TOO_HIGH: "HIGH",
    DenialReason.POLICY_DENY: "MEDIUM",
    DenialReason.POLICY_UNAVAILABLE: "HIGH",
    DenialReason.GATEWAY_REFUSED: "MEDIUM",
    DenialReason.GATEWAY_ERROR: "MEDIUM",
    DenialReason.CONFIRMATION_REQUIRED: "LOW",
    DenialReason.INTERNAL_ERROR: "HIGH",
}

assert set(_DENIAL_CATEGORY) == set(DenialReason), "every denial needs a category"
assert set(_DENIAL_SEVERITY) == set(DenialReason), "every denial needs a severity"


class PolicyDecision(BaseModel):
    """Result of the policy step. Deterministic, never model-derived."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    decision: Decision
    reason: str
    risk: RiskClass
    source: str = "local"
    policy_id: str | None = None


class PolicyEngine(Protocol):
    """Interface the OPA client will implement in v0.4."""

    def evaluate(self, request: ActionRequest, risk: RiskClass) -> PolicyDecision: ...


class LocalPolicyEngine:
    """Deny-by-default policy used until OPA is wired in.

    The rule set is intentionally trivial and hard-coded rather than
    configurable: this is the fallback that must not be tunable by whatever
    the AI is doing.

    MEDIUM returns CONFIRM, not DENY. The two mean different things — DENY
    says "this will never be allowed", CONFIRM says "this is allowed if a
    human agrees" — and collapsing them would make the audit trail lie about
    whether the action is permanently forbidden. Whether a confirmation is
    actually available is the engine's question, not the policy's.
    """

    #: Actions this build will never authorize regardless of capability.
    ALWAYS_DENY: frozenset[str] = frozenset(FORBIDDEN_ACTION_NAMES)

    #: Risk at or above which a human must agree.
    CONFIRM_AT_OR_ABOVE: RiskClass = RiskClass.MEDIUM

    def evaluate(self, request: ActionRequest, risk: RiskClass) -> PolicyDecision:
        name = request.action_name
        if name in self.ALWAYS_DENY:
            return PolicyDecision(
                decision=Decision.DENY,
                reason=f"{name} is permanently denied by policy",
                risk=risk,
                source="local:denylist",
            )
        if risk.rank >= RiskClass.CRITICAL.rank:
            return PolicyDecision(
                decision=Decision.DENY,
                reason="risk class CRITICAL is never authorized",
                risk=risk,
                source="local:risk-ceiling",
            )
        if risk.rank >= self.CONFIRM_AT_OR_ABOVE.rank:
            return PolicyDecision(
                decision=Decision.CONFIRM,
                reason=f"risk class {risk.value} requires explicit user confirmation",
                risk=risk,
                source="local:confirm-required",
            )
        return PolicyDecision(
            decision=Decision.ALLOW,
            reason=f"risk class {risk.value} is allowed by local policy",
            risk=risk,
            source="local:allow-low",
        )


class LedgerRecord(BaseModel):
    """What the engine hands to the audit layer for each transition."""

    model_config = ConfigDict(extra="forbid")

    action_id: str
    session_id: str
    agent_id: str
    action: str
    state: ActionState
    risk: RiskClass
    decision: Decision
    reason: str
    capability: str | None = None
    capability_reason: str | None = None
    target: str | None = None
    policy_source: str | None = None
    duration_ms: float | None = None
    at: datetime = Field(default_factory=utcnow)
    detail: str | None = None
    #: Set on the transition into a terminal state, and distinct from
    #: ``detail`` which carries whatever the failing step happened to say.
    #: Without this the actions table cannot record *why* it ended.
    denial_reason: str | None = None


class ActionLedger(Protocol):
    """Audit sink. The PostgreSQL implementation lands with the DB layer."""

    def record(self, entry: LedgerRecord) -> None: ...


class InMemoryLedger:
    """Ledger used by tests and by the CLI before a database is configured."""

    def __init__(self) -> None:
        self.entries: list[LedgerRecord] = []

    def record(self, entry: LedgerRecord) -> None:
        self.entries.append(entry)

    def by_action(self, action_id: str) -> list[LedgerRecord]:
        return [e for e in self.entries if e.action_id == action_id]

    def states(self, action_id: str) -> list[ActionState]:
        return [e.state for e in self.by_action(action_id)]


class Verdict(BaseModel):
    """Full security outcome for one action, including the executed result."""

    model_config = ConfigDict(extra="forbid")

    action_id: str
    action: str
    state: ActionState
    decision: Decision
    risk: RiskClass
    reason: str
    denial_reason: DenialReason | None = None
    capability: CapabilityCheck | None = None
    policy: PolicyDecision | None = None
    result: ActionResult | None = None
    observation: Observation | None = None
    at: datetime = Field(default_factory=utcnow)
    duration_ms: float | None = None


class SecurityEngine:
    """Validates, authorizes, and executes — in that order, logging each step."""

    def __init__(
        self,
        gateway: OSGateway,
        capability_manager: CapabilityManager | None = None,
        policy: PolicyEngine | None = None,
        ledger: ActionLedger | None = None,
        security_event_recorder: Callable[..., Any] | None = None,
    ) -> None:
        self.gateway = gateway
        self.capabilities = capability_manager or CapabilityManager()
        self.policy = policy or LocalPolicyEngine()
        self.ledger = ledger if ledger is not None else InMemoryLedger()
        #: Optional sink for security events (PostgresLedger in production).
        #: Denials are forwarded here so the detection-rate measurement reads
        #: from the same rows an operator would look at.
        self._security_events = security_event_recorder
        #: Audit rows the ledger failed to accept. Non-zero means the audit
        #: trail has a hole in it, which is itself a security signal.
        self.ledger_errors = 0

    # ------------------------------------------------------------ targets

    @staticmethod
    def declared_target(request: ActionRequest) -> str | None:
        """The resource an action targets, extracted from its params.

        Scope is checked against this, not against ``requested_scope`` — the
        latter is a claim by the proposer and must not be able to widen the
        real target.
        """
        dimension = scope_dimension_for(request.action_name)
        params = request.typed_params
        if dimension is ScopeDimension.PID:
            return str(params.pid)
        if dimension is ScopeDimension.PATH:
            return params.path
        if dimension is ScopeDimension.UID:
            return str(getattr(params, "uid", ""))
        return None

    @staticmethod
    def _check_scope_consistency(request: ActionRequest) -> None:
        """Reject a proposal whose declared scope disagrees with its params.

        The AI can claim to want ``/home/user/Downloads`` while carrying a
        path elsewhere. Comparing the two is cheap and closes a real bypass.
        """
        if not request.requested_scope:
            return
        dimension = scope_dimension_for(request.action_name)
        target = SecurityEngine.declared_target(request)
        for key, value in request.requested_scope.items():
            if key == "path" and target is not None and isinstance(value, str):
                if _normalise(value) != _normalise(target):
                    raise SecurityValidationError(
                        "requested_scope.path does not match the action target",
                        DenialReason.SCOPE_MISMATCH,
                    )
            elif key == "pid" and target is not None and str(value) != target:
                raise SecurityValidationError(
                    "requested_scope.pid does not match the action target",
                    DenialReason.SCOPE_MISMATCH,
                )
            elif key not in ("path", "pid", "uid"):
                raise SecurityValidationError(
                    f"requested_scope key {key!r} is not a scope dimension for this action",
                    DenialReason.SCOPE_MISMATCH,
                )
            elif dimension is ScopeDimension.NONE:
                raise SecurityValidationError(
                    f"{request.action_name} has no scope, so requested_scope must be empty",
                    DenialReason.SCOPE_MISMATCH,
                )

    # ------------------------------------------------------------ pipeline

    def authorize(self, request: ActionRequest) -> Verdict:
        """Run every check *except* execution. Used by the v0.4 API's
        dry-run mode and by tests that assert a denial without side effects."""
        return self._pipeline(request, execute=False)

    def process(self, request: ActionRequest) -> Verdict:
        """Full path: validate → authorize → execute, logging each transition."""
        return self._pipeline(request, execute=True)

    def _pipeline(self, request: ActionRequest, execute: bool) -> Verdict:
        started = time.perf_counter()
        name = request.action_name
        state = ActionState.PROPOSED
        risk = risk_for(name)

        # 1. Protocol validation. parse_ai_payload is not used here because the
        #    caller already holds a validated request, but the checks are
        #    repeated so a hand-constructed object cannot skip them.
        if name in FORBIDDEN_ACTION_NAMES:
            return self._deny(
                request, state, Decision.DENY, risk, DenialReason.FORBIDDEN_ACTION,
                f"{name} is forbidden", started,
            )
        if name not in self.gateway.supported_actions:
            return self._deny(
                request, state, Decision.DENY, risk, DenialReason.NOT_IN_PROTOCOL,
                f"{name} is not in the gateway whitelist", started,
            )
        if request.trust_domain is TrustDomain.T4_EXTERNAL and name in PATH_PARAM_ACTIONS:
            # External content asking for a path is the canonical injection
            # shape. It is denied at the engine, not merely low-trust.
            return self._deny(
                request, state, Decision.DENY, risk, DenialReason.POLICY_DENY,
                "external-origin proposals may not request filesystem paths", started,
            )

        try:
            self._check_scope_consistency(request)
        except SecurityValidationError as exc:
            return self._deny(
                request, state, Decision.DENY, risk, exc.reason, str(exc), started,
            )

        # 2. Lifecycle: PROPOSED -> VALIDATED
        state = self._transition(request, state, ActionState.VALIDATED, risk, Decision.ALLOW,
                                 "schema and structure valid")

        # 3. Capability check, scoped to the real target.
        target = self.declared_target(request)
        check = self.capabilities.check(request.agent_id, name, target)
        self._log(
            request, state, risk,
            Decision.ALLOW if check.allowed else Decision.DENY,
            check.reason, capability=check.matched_capability,
            capability_reason=check.reason, target=target,
        )
        if not check.allowed:
            return self._verdict(
                request, ActionState.VALIDATED, Decision.DENY, risk, check.reason,
                _classify_capability_denial(self.capabilities, request.agent_id, name, check),
                capability=check, started=started,
            )

        # 4. Policy decision — deterministic, independent of the model.
        policy = self.policy.evaluate(request, risk)
        self._log(
            request, ActionState.VALIDATED, risk, policy.decision, policy.reason,
            capability=check.matched_capability, target=target,
            policy_source=policy.source,
        )
        if policy.decision is Decision.DENY:
            return self._verdict(
                request, ActionState.VALIDATED, Decision.DENY, risk, policy.reason,
                DenialReason.POLICY_DENY, capability=check, policy=policy, started=started,
            )
        if policy.decision is Decision.CONFIRM:
            return self._verdict(
                request, ActionState.VALIDATED, Decision.CONFIRM, risk, policy.reason,
                DenialReason.CONFIRMATION_REQUIRED, capability=check, policy=policy,
                started=started,
            )

        # 5. AUTHORIZED
        state = self._transition(
            request, ActionState.VALIDATED, ActionState.AUTHORIZED, risk,
            Decision.ALLOW, policy.reason, capability=check.matched_capability,
            target=target, policy_source=policy.source,
        )

        if not execute:
            return self._verdict(
                request, state, Decision.ALLOW, risk, policy.reason, None,
                capability=check, policy=policy, started=started,
            )

        # 6. EXECUTE, only reachable from AUTHORIZED.
        try:
            observation, duration_ms = self.gateway.execute_timed(request)
        except (ActionNotPermitted, PreconditionFailed) as exc:
            return self._verdict(
                request, state, Decision.DENY, risk, str(exc),
                DenialReason.GATEWAY_REFUSED, capability=check, policy=policy,
                started=started,
            )
        except GatewayError as exc:
            return self._verdict(
                request, state, Decision.DENY, risk, str(exc),
                DenialReason.GATEWAY_ERROR, capability=check, policy=policy,
                started=started,
            )
        except Exception as exc:  # unexpected: fail closed, log, do not retry
            return self._verdict(
                request, state, Decision.DENY, risk, f"{type(exc).__name__}: {exc}",
                DenialReason.INTERNAL_ERROR, capability=check, policy=policy,
                started=started,
            )

        self._log(request, ActionState.EXECUTED, risk, Decision.ALLOW, "executed",
                  capability=check.matched_capability, target=target, duration_ms=duration_ms)

        # 7. OBSERVED, then COMPLETED.
        #
        # The gateway returning an Observation *is* the observation step for a
        # read-only action: provenance is already attached and the caller
        # receives it. Recording these two transitions is what lets the state
        # machine's happy path actually terminate, and it is the only thing
        # that sets completed_at — without them every successful action sat
        # at EXECUTED forever and looked, in the ledger, like it was still
        # running. Day 5's AI consumer sits at this boundary; nothing about
        # these two transitions assumes it.
        self._transition(
            request, ActionState.EXECUTED, ActionState.OBSERVED, risk, Decision.ALLOW,
            f"observation returned from {observation.source} "
            f"({observation.trust_domain.value})",
            capability=check.matched_capability, target=target,
        )
        self._transition(
            request, ActionState.OBSERVED, ActionState.COMPLETED, risk, Decision.ALLOW,
            "read-only action completed", duration_ms=duration_ms,
        )

        result = ActionResult(
            action_id=request.action_id,
            state=ActionState.COMPLETED,
            success=True,
            source=observation.source,
            trust_domain=observation.trust_domain,
            duration_ms=duration_ms,
        )
        return Verdict(
            action_id=request.action_id,
            action=name,
            state=ActionState.COMPLETED,
            decision=Decision.ALLOW,
            risk=risk,
            reason=policy.reason,
            capability=check,
            policy=policy,
            result=result,
            observation=observation,
            duration_ms=(time.perf_counter() - started) * 1000.0,
        )

    # ------------------------------------------------------------ helpers

    def _transition(
        self,
        request: ActionRequest,
        current: ActionState,
        to_state: ActionState,
        risk: RiskClass,
        decision: Decision,
        reason: str,
        **kwargs: Any,
    ) -> ActionState:
        assert_transition(current, to_state)
        self._log(request, to_state, risk, decision, reason, **kwargs)
        return to_state

    def _log(
        self,
        request: ActionRequest,
        state: ActionState,
        risk: RiskClass,
        decision: Decision,
        reason: str,
        **kwargs: Any,
    ) -> None:
        """Append one row to the audit trail.

        A ledger failure is logged and counted but never propagated. The
        decision has already been made by the time this runs, and letting a
        database outage escape would mean the caller retries a half-processed
        action — for an authorized action that is a second execution, not a
        no-op. Losing an audit row is bad; re-running an action is worse, and
        the dropped rows are counted so the gap is visible rather than silent.
        """
        try:
            self.ledger.record(
                LedgerRecord(
                    action_id=request.action_id,
                    session_id=request.session_id,
                    agent_id=request.agent_id,
                    action=request.action_name,
                    state=state,
                    risk=risk,
                    decision=decision,
                    reason=reason,
                    **kwargs,
                )
            )
        except Exception:
            self.ledger_errors += 1
            log.exception("ledger write failed for action %s", request.action_id)

    def _verdict(
        self,
        request: ActionRequest,
        state: ActionState,
        decision: Decision,
        risk: RiskClass,
        reason: str,
        denial: DenialReason | None,
        *,
        capability: CapabilityCheck | None = None,
        policy: PolicyDecision | None = None,
        started: float | None = None,
    ) -> Verdict:
        """Close out an action that is not going to execute.

        Every non-executing outcome lands in the terminal ``DENIED`` state,
        which is reachable from PROPOSED, VALIDATED and AUTHORIZED alike, and
        the transition is asserted so an unreachable branch fails loudly rather
        than quietly writing a DENIED row onto a state it never passed
        through. ``decision`` stays distinct from ``state`` so the audit trail
        can still tell "refused outright" from "waiting on a human" — a CONFIRM
        is not a permanent refusal, it is a refusal for now.
        """
        if denial is None and decision is Decision.ALLOW:
            terminal = state
        else:
            assert_transition(state, ActionState.DENIED)
            terminal = ActionState.DENIED
            self._log(
                request, ActionState.DENIED, risk, decision, reason,
                detail=denial.value if denial else None,
                denial_reason=denial.value if denial else None,
                capability=capability.matched_capability if capability else None,
            )
        if decision is Decision.DENY and denial is not None:
            self._record_security_event(request, denial, reason, risk)
        return Verdict(
            action_id=request.action_id,
            action=request.action_name,
            state=terminal,
            decision=decision,
            risk=risk,
            reason=reason,
            denial_reason=denial,
            capability=capability,
            policy=policy,
            duration_ms=(time.perf_counter() - started) * 1000.0 if started else None,
        )

    def _record_security_event(
        self,
        request: ActionRequest,
        denial: DenialReason,
        reason: str,
        risk: RiskClass,
    ) -> None:
        """Forward a denial to the security-event sink.

        Wrapped so a logging failure can never change a decision that was
        already made: a denial stays a denial even if the database is gone.
        """
        if self._security_events is None:
            return
        try:
            self._security_events(
                category=_DENIAL_CATEGORY[denial],
                severity=_DENIAL_SEVERITY[denial],
                summary=f"{request.action_name} denied: {reason}"[:500],
                agent_id=request.agent_id,
                session_id=request.session_id,
                action_id=request.action_id,
                details={
                    "action": request.action_name,
                    "denial_reason": denial.value,
                    "risk": risk.value,
                    "origin": request.trust_domain.value,
                    "params": request.params,
                    "intent": request.intent,
                },
            )
        except Exception:  # pragma: no cover - defensive
            log.exception("security event recording failed for %s", request.action_id)

    def _deny(
        self,
        request: ActionRequest,
        state: ActionState,
        decision: Decision,
        risk: RiskClass,
        denial: DenialReason,
        reason: str,
        started: float,
    ) -> Verdict:
        # The refusing step is recorded at the state it refused *from*, so the
        # trail shows where the action died and not merely that it did. The
        # transition into the terminal state is _verdict's job.
        self._log(request, state, risk, decision, reason, detail=denial.value)
        return self._verdict(
            request, state, decision, risk, reason, denial, started=started
        )


class SecurityValidationError(ValueError):
    def __init__(self, message: str, reason: DenialReason) -> None:
        super().__init__(message)
        self.reason = reason


def _classify_capability_denial(
    manager: CapabilityManager,
    agent_id: str,
    action: str,
    check: CapabilityCheck,
) -> DenialReason:
    """Turn a capability refusal into a specific, countable reason.

    Order: expiry, then revocation, then absence of a grant, then scope. These
    are four different operational problems and the audit table should be able
    to tell them apart.
    """
    if check.expired:
        return DenialReason.CAPABILITY_EXPIRED
    if manager.is_revoked(agent_id, action):
        return DenialReason.CAPABILITY_REVOKED
    if not manager.has(agent_id, action):
        return DenialReason.CAPABILITY_MISSING
    return DenialReason.SCOPE_MISMATCH


def new_action_id(prefix: str = "act") -> str:
    return f"{prefix}-{uuid.uuid4().hex[:16]}"


def make_ai_request(
    action: str,
    params: dict[str, Any] | None = None,
    *,
    agent_id: str = "local-agent",
    session_id: str = "cli",
    origin: DataOrigin = DataOrigin.AI,
    requested_scope: dict[str, Any] | None = None,
    intent: str | None = None,
) -> ActionRequest:
    """Build a request the way the AI path will, for tests and the CLI."""
    from aios.models.actions import PARAMS_MAP, ActionError, ActionType

    if action in FORBIDDEN_ACTION_NAMES:
        raise ActionError(f"{action} is forbidden")
    if action not in PARAMS_MAP:
        raise ActionError(f"unknown action {action}")
    return ActionRequest(
        action_id=new_action_id(),
        agent_id=agent_id,
        session_id=session_id,
        type=ActionType(action),
        params=params or {},
        origin=origin,
        requested_scope=requested_scope or {},
        intent=intent,
    )
