"""Capability Manager — issues, stores, and checks capability grants.

Two invariants, both tested:

1. **Deny by default.** A check for an action the agent has no grant for
   returns a decision of DENY, not a default-allow.
2. **No implication.** ``process.list`` never implies ``process.inspect``,
   and ``filesystem.list`` on a directory never implies ``filesystem.read``
   of a file inside it. Grants are matched by exact action name.

Grants are in-memory for this build. The persistence layer records them in
PostgreSQL so the ledger can reconstruct why an action was authorized, but
issue-time trust decisions come from here.
"""

from __future__ import annotations

import threading
from collections.abc import Iterable
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict

from aios.models.common import utcnow
from aios.security.capabilities import (
    DEFAULT_CAPABILITIES,
    Capability,
    ScopeDimension,
    path_in_scope,
    pid_in_scope,
    risk_for,
    scope_dimension_for,
    uid_in_scope,
)


class CapabilityCheck(BaseModel):
    """Result of checking one action against one agent's grants."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    agent_id: str
    action: str
    allowed: bool
    reason: str
    matched_capability: str | None = None
    target: str | None = None
    dimension: str = ScopeDimension.NONE.value
    risk: str = risk_for("__unknown__").value
    expired: bool = False


class CapabilityManager:
    """Owns the grant table for all agents."""

    def __init__(self, default_grants: Iterable[Capability] | None = None) -> None:
        self._lock = threading.RLock()
        self._grants: dict[str, list[Capability]] = {}
        self._revoked: dict[str, list[Capability]] = {}
        if default_grants is not None:
            for cap in default_grants:
                self.grant("local-agent", cap)
        else:
            for cap in DEFAULT_CAPABILITIES:
                self.grant("local-agent", cap)

    # ------------------------------------------------------------ mutation

    def grant(self, agent_id: str, capability: Capability) -> Capability:
        with self._lock:
            bucket = self._grants.setdefault(agent_id, [])
            # Re-granting the same action replaces the previous scope rather
            # than widening it silently. Widening must be a visible act.
            bucket[:] = [c for c in bucket if c.action != capability.action]
            bucket.append(capability)
            # A fresh grant also clears any prior revocation for that action.
            self._revoked[agent_id] = [
                c for c in self._revoked.get(agent_id, []) if c.action != capability.action
            ]
        return capability

    def grant_action(
        self,
        agent_id: str,
        action: str,
        scope: Iterable[str] | None = None,
        *,
        expires_at: datetime | None = None,
        reason: str | None = None,
    ) -> Capability:
        return self.grant(
            agent_id,
            Capability(
                action=action,
                scope=tuple(scope or ()),
                expires_at=expires_at,
                reason=reason,
            ),
        )

    def revoke(self, agent_id: str, action: str) -> bool:
        """Revoke an action for an agent. Revocation is sticky until re-granted."""
        with self._lock:
            bucket = self._grants.get(agent_id, [])
            removed = [c for c in bucket if c.action == action]
            if not removed:
                return False
            bucket[:] = [c for c in bucket if c.action != action]
            self._revoked.setdefault(agent_id, []).extend(removed)
            return True

    def revoke_all(self, agent_id: str) -> int:
        with self._lock:
            bucket = self._grants.get(agent_id, [])
            count = len(bucket)
            self._revoked[agent_id] = list(bucket)
            self._grants[agent_id] = []
            return count

    # ------------------------------------------------------------ queries

    def capabilities_for(self, agent_id: str) -> list[Capability]:
        with self._lock:
            return list(self._grants.get(agent_id, []))

    def has(self, agent_id: str, action: str) -> bool:
        return any(c.action == action for c in self.capabilities_for(agent_id))

    def is_revoked(self, agent_id: str, action: str) -> bool:
        with self._lock:
            return any(c.action == action for c in self._revoked.get(agent_id, []))

    def all_agents(self) -> list[str]:
        with self._lock:
            return sorted(set(self._grants) | set(self._revoked))

    def describe(self, agent_id: str) -> dict[str, Any]:
        with self._lock:
            return {
                "agent_id": agent_id,
                "granted": [c.to_dict() for c in self._grants.get(agent_id, [])],
                "revoked": [c.to_dict() for c in self._revoked.get(agent_id, [])],
            }

    # ------------------------------------------------------------ checking

    def check(
        self,
        agent_id: str,
        action: str,
        target: str | None = None,
        now: datetime | None = None,
    ) -> CapabilityCheck:
        """Check one action, optionally against a scoped target.

        Order matters: revocation is checked before grants, and expiry before
        scope. A revoked action stays denied even if a matching grant object
        somehow remains in the table.
        """
        now = now or utcnow()
        dimension = scope_dimension_for(action)
        risk = risk_for(action).value

        if self.is_revoked(agent_id, action):
            return CapabilityCheck(
                agent_id=agent_id,
                action=action,
                allowed=False,
                reason="capability was revoked for this agent",
                dimension=dimension.value,
                risk=risk,
            )

        candidates = [c for c in self.capabilities_for(agent_id) if c.action == action]
        if not candidates:
            return CapabilityCheck(
                agent_id=agent_id,
                action=action,
                allowed=False,
                reason="no capability grant for this action (deny by default)",
                dimension=dimension.value,
                risk=risk,
            )

        # A numeric dimension with a non-numeric target is denied before any
        # pattern is consulted. Otherwise a '*' scope would match a target the
        # rest of the stack could not even resolve.
        numeric_target: int | None = None
        if dimension in (ScopeDimension.PID, ScopeDimension.UID) and target is not None:
            try:
                numeric_target = int(target)
            except (TypeError, ValueError):
                return CapabilityCheck(
                    agent_id=agent_id,
                    action=action,
                    allowed=False,
                    reason=f"target {target!r} is not a valid {dimension.value}",
                    dimension=dimension.value,
                    risk=risk,
                    target=target,
                )

        for cap in candidates:
            if cap.is_expired(now):
                continue
            if dimension is ScopeDimension.NONE or target is None:
                return CapabilityCheck(
                    agent_id=agent_id,
                    action=action,
                    allowed=True,
                    reason="capability granted",
                    matched_capability=cap.display(),
                    target=target,
                    dimension=dimension.value,
                    risk=risk,
                )
            if dimension is ScopeDimension.PATH and path_in_scope(target, cap.scope):
                return CapabilityCheck(
                    agent_id=agent_id,
                    action=action,
                    allowed=True,
                    reason="target is within capability scope",
                    matched_capability=cap.display(),
                    target=target,
                    dimension=dimension.value,
                    risk=risk,
                )
            if dimension is ScopeDimension.PID and pid_in_scope(numeric_target, cap.scope):
                return CapabilityCheck(
                    agent_id=agent_id,
                    action=action,
                    allowed=True,
                    reason="target is within capability scope",
                    matched_capability=cap.display(),
                    target=target,
                    dimension=dimension.value,
                    risk=risk,
                )
            if dimension is ScopeDimension.UID and uid_in_scope(numeric_target, cap.scope):
                return CapabilityCheck(
                    agent_id=agent_id,
                    action=action,
                    allowed=True,
                    reason="target is within capability scope",
                    matched_capability=cap.display(),
                    target=target,
                    dimension=dimension.value,
                    risk=risk,
                )

        if all(c.is_expired(now) for c in candidates):
            return CapabilityCheck(
                agent_id=agent_id,
                action=action,
                allowed=False,
                reason="capability has expired",
                dimension=dimension.value,
                risk=risk,
                expired=True,
            )
        return CapabilityCheck(
            agent_id=agent_id,
            action=action,
            allowed=False,
            reason=(
                f"target {target!r} is outside every granted scope for {action}"
            ),
            dimension=dimension.value,
            risk=risk,
            target=target,
        )
