"""The Action Protocol — the only interface between AI and the OS.

Design rules enforced here:

* The action ``type`` is a closed enum. An unknown type is a validation error,
  not a fallback to some generic handler.
* Every action declares its required parameters explicitly, so a handler
  cannot receive an unvalidated field it did not ask for.
* Extra fields are forbidden on every model, so nothing can be smuggled
  alongside a valid action.
* Targets are typed and range-checked. There is no free-form string target
  that a handler might later interpret.
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from aios.actions.catalog import FORBIDDEN_ACTIONS
from aios.models.common import DataOrigin, TrustDomain, utcnow
from aios.models.lifecycle import ActionState

#: Actions permitted in this build. Observation actions are executed by the
#: read-only gateway; quarantine and restore are served by the mutation
#: executor and always require a plan and an approval token.
ActionType = Enum(
    "ActionType",
    {
        "SYSTEM_CPU": "system.cpu",
        "SYSTEM_MEMORY": "system.memory",
        "SYSTEM_HOSTNAME": "system.hostname",
        "SYSTEM_STATUS": "system.status",
        "SYSTEM_UPTIME": "system.uptime",
        "PROCESS_LIST": "process.list",
        "PROCESS_INSPECT": "process.inspect",
        "NETWORK_CONNECTIONS": "network.connections",
        "FILESYSTEM_LIST": "filesystem.list",
        "FILESYSTEM_STAT": "filesystem.stat",
        "FILESYSTEM_READ": "filesystem.read",
        "FILESYSTEM_CLEANUP_SCAN": "filesystem.cleanup_scan",
        "FILESYSTEM_QUARANTINE": "filesystem.quarantine",
        "FILESYSTEM_RESTORE": "filesystem.restore",
    },
)

#: Mutating operation names that must never appear in an AI proposal. Sourced
#: from the action catalog so the protocol and the catalog cannot drift.
FORBIDDEN_ACTION_NAMES = FORBIDDEN_ACTIONS


class ActionError(ValueError):
    """Raised when a proposed action cannot be accepted as-is."""


class _Base(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)


# ---------------------------------------------------------------- payloads


class SystemCpuParams(_Base):
    interval_s: float = Field(default=0.25, ge=0.0, le=5.0)
    include_frequencies: bool = True


class SystemMemoryParams(_Base):
    include_swap: bool = True
    include_fields: bool = False


class SystemHostnameParams(_Base):
    pass


class SystemStatusParams(_Base):
    include_disks: bool = True
    include_thermal: bool = True


class SystemUptimeParams(_Base):
    pass


SORT_FIELDS = ("cpu", "memory", "pid", "name")


class ProcessListParams(_Base):
    limit: int = Field(default=50, ge=1, le=1000)
    sort_by: Literal["cpu", "memory", "pid", "name"] = "cpu"
    name_filter: str | None = Field(default=None, max_length=64)
    uid_filter: int | None = Field(default=None, ge=0)
    include_cmdline: bool = False

    @field_validator("name_filter")
    @classmethod
    def _no_control_chars(cls, v: str | None) -> str | None:
        if v and any(ord(c) < 0x20 or ord(c) == 0x7F for c in v):
            raise ValueError("name_filter must not contain control characters")
        return v


class ProcessInspectParams(_Base):
    pid: int = Field(ge=1, le=4_194_303)
    include_extras: bool = True


STATE_FILTERS = (
    "ESTABLISHED", "LISTEN", "SYN_SENT", "SYN_RECV", "FIN_WAIT1", "FIN_WAIT2",
    "TIME_WAIT", "CLOSE", "CLOSE_WAIT", "LAST_ACK", "CLOSING",
)


class NetworkConnectionsParams(_Base):
    limit: int = Field(default=200, ge=1, le=2000)
    include_unix: bool = False
    attribute_pids: bool = True
    listening_only: bool = False
    states: list[Literal[STATE_FILTERS]] | None = Field(default=None, max_length=11)

    @field_validator("states")
    @classmethod
    def _dedupe_states(cls, v: list[str] | None) -> list[str] | None:
        if v is None:
            return None
        seen: list[str] = []
        for state in v:
            if state not in seen:
                seen.append(state)
        return seen


class FilesystemListParams(_Base):
    path: str | None = Field(default=None, max_length=4096)
    include_pseudo: bool = False
    max_entries: int = Field(default=500, ge=1, le=5000)
    show_hidden: bool = False

    @field_validator("path")
    @classmethod
    def _reject_nul(cls, v: str | None) -> str | None:
        if v is not None and "\0" in v:
            raise ValueError("path must not contain NUL")
        return v


class FilesystemStatParams(_Base):
    path: str = Field(max_length=4096)

    @field_validator("path")
    @classmethod
    def _reject_nul(cls, v: str) -> str:
        if "\0" in v:
            raise ValueError("path must not contain NUL")
        if not v:
            raise ValueError("path must not be empty")
        return v


class FilesystemReadParams(_Base):
    path: str = Field(max_length=4096)
    max_bytes: int = Field(default=65_536, ge=1, le=1_048_576)

    @field_validator("path")
    @classmethod
    def _reject_nul(cls, v: str) -> str:
        if "\0" in v:
            raise ValueError("path must not contain NUL")
        if not v:
            raise ValueError("path must not be empty")
        return v


class FilesystemCleanupScanParams(_Base):
    """Read-only scan for cleanup candidates under ``path``."""

    path: str = Field(max_length=4096)
    min_age_days: int = Field(default=30, ge=0, le=3650)
    min_size_bytes: int = Field(default=0, ge=0)
    max_candidates: int = Field(default=500, ge=1, le=5000)
    include_hidden: bool = False

    @field_validator("path")
    @classmethod
    def _reject_nul(cls, v: str) -> str:
        if "\0" in v:
            raise ValueError("path must not contain NUL")
        if not v:
            raise ValueError("path must not be empty")
        return v


class _PlanTargetParams(_Base):
    """Common fields for a mutation step bound to an approved plan."""

    path: str = Field(max_length=4096)
    plan_id: str = Field(min_length=8, max_length=64, pattern=r"^plan-[A-Za-z0-9_-]+$")
    candidate_id: str = Field(
        min_length=8, max_length=64, pattern=r"^c-[A-Za-z0-9_-]+$"
    )

    @field_validator("path")
    @classmethod
    def _reject_nul(cls, v: str) -> str:
        if "\0" in v:
            raise ValueError("path must not contain NUL")
        if not v:
            raise ValueError("path must not be empty")
        return v


class FilesystemQuarantineParams(_PlanTargetParams):
    """Move an approved cleanup candidate into quarantine."""


class FilesystemRestoreParams(_PlanTargetParams):
    """Restore a quarantined candidate to its recorded original path."""


# ---------------------------------------------------------------- envelope


#: The single source of truth for which action types exist and what each one
#: accepts. Adding a key here is the only way to add an action: a type absent
#: from this map cannot be constructed, so the gateway registry and the
#: protocol cannot drift apart.
PARAMS_MAP: dict[str, type[_Base]] = {
    "system.cpu": SystemCpuParams,
    "system.memory": SystemMemoryParams,
    "system.hostname": SystemHostnameParams,
    "system.status": SystemStatusParams,
    "system.uptime": SystemUptimeParams,
    "process.list": ProcessListParams,
    "process.inspect": ProcessInspectParams,
    "network.connections": NetworkConnectionsParams,
    "filesystem.list": FilesystemListParams,
    "filesystem.stat": FilesystemStatParams,
    "filesystem.read": FilesystemReadParams,
    "filesystem.cleanup_scan": FilesystemCleanupScanParams,
    "filesystem.quarantine": FilesystemQuarantineParams,
    "filesystem.restore": FilesystemRestoreParams,
}

def params_model_for(action_type: str) -> type[_Base] | None:
    """Params model for an action type, or None if the type is unknown."""
    return PARAMS_MAP.get(action_type)


class ActionRequest(_Base):
    """A proposed action. Produced by the AI, validated by the Security Engine.

    Note there is no ``command`` or ``args`` field, and no way to add one:
    ``extra="forbid"`` plus the closed ``type`` enum means the wire format
    cannot express an arbitrary command.
    """

    action_id: str = Field(min_length=8, max_length=64, pattern=r"^[A-Za-z0-9_-]+$")
    agent_id: str = Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9_.-]+$")
    session_id: str = Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9_-]+$")
    type: ActionType
    params: dict[str, Any] = Field(default_factory=dict)
    intent: str | None = Field(default=None, max_length=256)
    requested_scope: dict[str, Any] = Field(default_factory=dict)
    origin: DataOrigin = DataOrigin.AI

    @model_validator(mode="after")
    def _validate_type_against_params(self) -> ActionRequest:
        value = self.type.value
        expected = PARAMS_MAP[value]
        if self.params:
            # Validates and rejects unknown keys for this action type.
            try:
                expected.model_validate(self.params)
            except Exception as exc:
                raise ValueError(f"invalid params for {value}: {exc}") from exc
        if value in FORBIDDEN_ACTION_NAMES:
            raise ValueError(f"action type {value} is not permitted")
        return self

    @property
    def action_name(self) -> str:
        return self.type.value

    @property
    def typed_params(self) -> _Base:
        return PARAMS_MAP[self.action_name].model_validate(self.params or {})

    @property
    def trust_domain(self) -> TrustDomain:
        from aios.models.common import ORIGIN_TRUST

        return ORIGIN_TRUST[self.origin]


class ActionResult(_Base):
    """Outcome of an action. ``data`` is the payload; it carries its own
    provenance envelope from the gateway that produced it."""

    action_id: str
    state: ActionState
    success: bool
    data: dict[str, Any] | None = None
    error: str | None = None
    source: str | None = None
    trust_domain: TrustDomain | None = None
    duration_ms: float | None = None
    completed_at: Any = Field(default_factory=utcnow)


def make_request(
    action_type: str | ActionType,
    *,
    agent_id: str = "local-agent",
    session_id: str = "test-session",
    action_id: str = "test-action-0001",
    params: dict[str, Any] | None = None,
    intent: str | None = None,
) -> ActionRequest:
    """Convenience constructor for tests and the CLI."""
    value = action_type.value if isinstance(action_type, ActionType) else action_type
    if value in FORBIDDEN_ACTION_NAMES:
        raise ActionError(f"action type {value} is forbidden")
    if value not in PARAMS_MAP:
        raise ActionError(f"unknown action type: {value}")
    return ActionRequest(
        action_id=action_id,
        agent_id=agent_id,
        session_id=session_id,
        type=ActionType(value),
        params=params or {},
        intent=intent,
    )
