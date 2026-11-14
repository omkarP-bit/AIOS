"""Capability model and scope matching.

A capability is ``<action>`` optionally narrowed by scope. The critical
property is that **absence of a capability denies**. There is no wildcard, no
implication, and no prefix matching that would let ``process.list`` imply
``process.terminate``.
"""

from __future__ import annotations

import fnmatch
import re
from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, field_validator, model_validator

from aios.models.actions import PARAMS_MAP
from aios.models.common import utcnow


class RiskClass(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    @property
    def rank(self) -> int:
        return {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}[self.value]


#: Per-action risk. Fixed table, not computed from AI input, so a proposal
#: cannot argue itself into a lower class.
ACTION_RISK: dict[str, RiskClass] = {
    "system.cpu": RiskClass.LOW,
    "system.memory": RiskClass.LOW,
    "system.hostname": RiskClass.LOW,
    "system.status": RiskClass.LOW,
    "system.uptime": RiskClass.LOW,
    "process.list": RiskClass.LOW,
    "process.inspect": RiskClass.LOW,
    "network.connections": RiskClass.LOW,
    "filesystem.list": RiskClass.LOW,
    # stat reveals ownership and existence; still read-only, but the target
    # path is the sensitive part, which scope handles.
    "filesystem.stat": RiskClass.LOW,
    # read returns attacker-controlled bytes into the AI's context. Highest
    # risk of the read-only set by design, not by accident.
    "filesystem.read": RiskClass.MEDIUM,
    # Scan is read-only but enumerates a tree, so it is scoped to a path.
    "filesystem.cleanup_scan": RiskClass.LOW,
    # Mutation. HIGH means a human-approved plan is mandatory.
    "filesystem.quarantine": RiskClass.HIGH,
    "filesystem.restore": RiskClass.HIGH,
}

#: Decision required before execution, by risk.
RISK_DECISION: dict[RiskClass, str] = {
    RiskClass.LOW: "ALLOW",
    RiskClass.MEDIUM: "CONFIRM",
    RiskClass.HIGH: "DENY",
    RiskClass.CRITICAL: "DENY",
}


class ScopeDimension(str, Enum):
    """What a capability's scope constrains.

    Only the dimensions that exist in the current protocol are modelled. New
    actions must either reuse one or add a dimension here, so that a scope
    that cannot be expressed is a type error rather than a runtime surprise.
    """

    PATH = "path"
    PID = "pid"
    UID = "uid"
    NONE = "none"


#: Which scope dimension constrains which action. An action not listed here
#: takes no scope, and a capability granting it with a scope is rejected.
ACTION_SCOPE_DIMENSION: dict[str, ScopeDimension] = {
    "system.cpu": ScopeDimension.NONE,
    "system.memory": ScopeDimension.NONE,
    "system.hostname": ScopeDimension.NONE,
    "system.status": ScopeDimension.NONE,
    "system.uptime": ScopeDimension.NONE,
    "process.list": ScopeDimension.NONE,
    "process.inspect": ScopeDimension.PID,
    "network.connections": ScopeDimension.NONE,
    "filesystem.list": ScopeDimension.PATH,
    "filesystem.stat": ScopeDimension.PATH,
    "filesystem.read": ScopeDimension.PATH,
    "filesystem.cleanup_scan": ScopeDimension.PATH,
    "filesystem.quarantine": ScopeDimension.PATH,
    "filesystem.restore": ScopeDimension.PATH,
}

#: Actions whose params carry a 'path' key, used for defence in depth.
PATH_PARAM_ACTIONS = frozenset(
    {a for a, d in ACTION_SCOPE_DIMENSION.items() if d is ScopeDimension.PATH}
)


def risk_for(action: str) -> RiskClass:
    """Risk class for an action. Unknown actions are CRITICAL, never LOW."""
    return ACTION_RISK.get(action, RiskClass.CRITICAL)


def scope_dimension_for(action: str) -> ScopeDimension:
    return ACTION_SCOPE_DIMENSION.get(action, ScopeDimension.NONE)


class Capability(BaseModel):
    """A grant: this agent may perform this action, within this scope.

    ``scope`` is a list of glob patterns. An empty list means *unscoped*,
    which is only valid for actions whose dimension is NONE.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    action: str
    scope: tuple[str, ...] = ()
    #: Expiry is enforced on every check, not only at grant time.
    expires_at: datetime | None = None
    granted_by: str = "capability-manager"
    reason: str | None = None

    @field_validator("action")
    @classmethod
    def _known_action(cls, v: str) -> str:
        if v not in PARAMS_MAP:
            raise ValueError(f"unknown action in capability: {v}")
        return v

    @model_validator(mode="after")
    def _scope_matches_dimension(self) -> Capability:
        dimension = scope_dimension_for(self.action)
        if self.scope and dimension is ScopeDimension.NONE:
            raise ValueError(
                f"{self.action} takes no scope; remove scope or use a scoped action"
            )
        if dimension is ScopeDimension.NONE and not self.scope:
            return self
        for pattern in self.scope:
            if not pattern or pattern.startswith("/") and pattern.count("/") == 0:
                raise ValueError(f"scope pattern must be a non-empty path: {pattern!r}")
        return self

    @property
    def dimension(self) -> ScopeDimension:
        return scope_dimension_for(self.action)

    def is_expired(self, now: datetime | None = None) -> bool:
        if self.expires_at is None:
            return False
        return (now or utcnow()) >= self.expires_at

    def display(self) -> str:
        return f"{self.action}{':' + ','.join(self.scope) if self.scope else ''}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "action": self.action,
            "scope": list(self.scope),
            "dimension": self.dimension.value,
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "granted_by": self.granted_by,
            "reason": self.reason,
        }


class ScopeViolation(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    reason: str
    target: str
    scope: tuple[str, ...]


def _normalise(path: str) -> str:
    """Canonicalise a path for comparison.

    ``..`` is collapsed, duplicate separators removed, and a trailing slash
    dropped, so ``/home/u/./Downloads/../Downloads/x`` cannot be used to slip
    past a pattern that matches the canonical form.
    """
    if not path:
        return path
    parts: list[str] = []
    for segment in path.split("/"):
        if segment in ("", "."):
            continue
        if segment == "..":
            if parts:
                parts.pop()
            continue
        parts.append(segment)
    normalised = "/" + "/".join(parts)
    return normalised or "/"


def path_in_scope(path: str, patterns: tuple[str, ...] | list[str]) -> bool:
    """True if ``path`` falls under any pattern.

    Matching is done on the normalised path, and a pattern ending in ``/*``
    matches everything beneath that prefix but not the prefix itself. Symlinks
    are not followed here: the gateway re-checks the resolved path, and
    resolving twice in two layers would hide which layer made the decision.
    """
    if not patterns:
        return False
    candidate = _normalise(path)
    return any(_matches(candidate, pattern) for pattern in patterns)


def _matches(candidate: str, pattern: str) -> bool:
    normalised_pattern = _normalise(pattern.rstrip("/")) if "/" in pattern else pattern
    if pattern.endswith("/*"):
        prefix = _normalise(pattern[:-2])
        if candidate == prefix:
            return False
        return candidate.startswith(prefix + "/")
    if "*" in normalised_pattern or "?" in normalised_pattern or "[" in normalised_pattern:
        # fnmatch on a segment-wise basis: '*' must not cross a '/' boundary,
        # otherwise '/home/*' would match '/home/u/.ssh/id_rsa' *and*
        # '/home/user/../other' patterns would be equivalent to '/'.
        return _fnmatch_segments(candidate, normalised_pattern)
    return candidate == normalised_pattern


def _fnmatch_segments(candidate: str, pattern: str) -> bool:
    """Segment-wise glob.

    ``*`` and ``?`` match within a single path segment and never across ``/``.
    That is the whole point: a plain ``fnmatch`` on the full string would make
    ``/home/*`` match ``/home/user/.ssh/id_rsa``, quietly turning a
    one-directory grant into a home-directory grant.

    ``**`` is the only construct that spans segments.
    """
    cand_parts = [p for p in candidate.strip("/").split("/") if p]
    pat_parts = [p for p in pattern.strip("/").split("/") if p]
    return _match_from(cand_parts, 0, pat_parts, 0)


def _match_from(
    cand: list[str], ci: int, pat: list[str], pi: int
) -> bool:
    if pi == len(pat):
        # Pattern exhausted: the candidate must be too, or we under-matched.
        return ci == len(cand)
    if pat[pi] == "**":
        # '**' absorbs zero or more remaining segments.
        return _match_from(cand, ci, pat, pi + 1) or (
            ci < len(cand) and _match_from(cand, ci + 1, pat, pi)
        )
    if ci >= len(cand) or not fnmatch.fnmatchcase(cand[ci], pat[pi]):
        return False
    return _match_from(cand, ci + 1, pat, pi + 1)


def pid_in_scope(pid: int, patterns: tuple[str, ...] | list[str]) -> bool:
    """True if a pid matches any scope pattern.

    Supports a bare number, a range (``1000-2000``), a list (``1,2,3``), and
    globs over the numeric string. ``*`` alone means any pid.
    """
    if not patterns:
        return False
    value = str(pid)
    for pattern in patterns:
        pattern = pattern.strip()
        if pattern == "*":
            return True
        if re.fullmatch(r"\d+", pattern):
            if int(pattern) == pid:
                return True
            continue
        if re.fullmatch(r"(\d+)-(\d+)", pattern):
            low, high = (int(x) for x in pattern.split("-"))
            if low <= pid <= high:
                return True
            continue
        if "," in pattern:
            if any(part.strip() == value for part in pattern.split(",")):
                return True
            continue
        if fnmatch.fnmatchcase(value, pattern):
            return True
    return False


def uid_in_scope(uid: int, patterns: tuple[str, ...] | list[str]) -> bool:
    return pid_in_scope(uid, patterns)


#: Default grants for the local agent: read-only system visibility, no
#: filesystem paths. A user who wants file reads must grant them explicitly,
#: with a path.
DEFAULT_CAPABILITIES: tuple[Capability, ...] = (
    Capability(action="system.cpu", reason="system visibility"),
    Capability(action="system.memory", reason="system visibility"),
    Capability(action="system.hostname", reason="system visibility"),
    Capability(action="system.status", reason="system visibility"),
    Capability(action="system.uptime", reason="system visibility"),
    Capability(action="process.list", reason="process visibility"),
    Capability(action="network.connections", reason="network visibility"),
)
