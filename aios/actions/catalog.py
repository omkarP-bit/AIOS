"""Language-neutral action catalog.

One descriptor per action. This module has no dependencies on the protocol or
the security engine, so it can be shared by Python, the future Go core, and
the Rego data generator without an import cycle.

The catalog describes what an action *is*. Rego decides whether a particular
proposal may run.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

CATALOG_VERSION = "2026-11-13"


class Effect(str, Enum):
    OBSERVE = "OBSERVE"
    STAGE = "STAGE"
    REVERSIBLE = "REVERSIBLE"
    DESTRUCTIVE = "DESTRUCTIVE"
    FORBIDDEN = "FORBIDDEN"


class ApprovalClass(str, Enum):
    NONE = "none"
    CONFIRM = "confirm"
    PLAN = "plan"


@dataclass(frozen=True)
class ActionDescriptor:
    id: str
    effect: Effect
    risk: str
    scope: str
    approval: ApprovalClass
    read_only: bool
    path_action: bool
    inverse: str | None = None
    limits: dict[str, int] = field(default_factory=dict)
    owasp: tuple[str, ...] = ()
    version: int = 1


#: Actions served by the mutation executor rather than the read-only gateway.
EXECUTOR_ACTIONS = frozenset({"filesystem.quarantine", "filesystem.restore"})

CATALOG: dict[str, ActionDescriptor] = {
    "system.cpu": ActionDescriptor(
        id="system.cpu", effect=Effect.OBSERVE, risk="LOW", scope="none",
        approval=ApprovalClass.NONE, read_only=True, path_action=False,
        owasp=("OWASP-A01:2021", "OWASP-ASVS4-V4"),
    ),
    "system.memory": ActionDescriptor(
        id="system.memory", effect=Effect.OBSERVE, risk="LOW", scope="none",
        approval=ApprovalClass.NONE, read_only=True, path_action=False,
        owasp=("OWASP-A01:2021",),
    ),
    "system.hostname": ActionDescriptor(
        id="system.hostname", effect=Effect.OBSERVE, risk="LOW", scope="none",
        approval=ApprovalClass.NONE, read_only=True, path_action=False,
        owasp=("OWASP-A01:2021",),
    ),
    "system.status": ActionDescriptor(
        id="system.status", effect=Effect.OBSERVE, risk="LOW", scope="none",
        approval=ApprovalClass.NONE, read_only=True, path_action=False,
        owasp=("OWASP-A01:2021",),
    ),
    "system.uptime": ActionDescriptor(
        id="system.uptime", effect=Effect.OBSERVE, risk="LOW", scope="none",
        approval=ApprovalClass.NONE, read_only=True, path_action=False,
        owasp=("OWASP-A01:2021",),
    ),
    "process.list": ActionDescriptor(
        id="process.list", effect=Effect.OBSERVE, risk="LOW", scope="none",
        approval=ApprovalClass.NONE, read_only=True, path_action=False,
        owasp=("OWASP-A01:2021", "OWASP-LLM01:2025"),
    ),
    "process.inspect": ActionDescriptor(
        id="process.inspect", effect=Effect.OBSERVE, risk="LOW", scope="pid",
        approval=ApprovalClass.NONE, read_only=True, path_action=False,
        owasp=("OWASP-A01:2021", "OWASP-LLM01:2025"),
    ),
    "network.connections": ActionDescriptor(
        id="network.connections", effect=Effect.OBSERVE, risk="LOW", scope="none",
        approval=ApprovalClass.NONE, read_only=True, path_action=False,
        owasp=("OWASP-A01:2021",),
    ),
    "filesystem.list": ActionDescriptor(
        id="filesystem.list", effect=Effect.OBSERVE, risk="LOW", scope="path",
        approval=ApprovalClass.NONE, read_only=True, path_action=True,
        owasp=("OWASP-A01:2021", "OWASP-ASVS4-V12"),
    ),
    "filesystem.stat": ActionDescriptor(
        id="filesystem.stat", effect=Effect.OBSERVE, risk="LOW", scope="path",
        approval=ApprovalClass.NONE, read_only=True, path_action=True,
        owasp=("OWASP-A01:2021", "OWASP-ASVS4-V12"),
    ),
    "filesystem.read": ActionDescriptor(
        id="filesystem.read", effect=Effect.OBSERVE, risk="MEDIUM", scope="path",
        approval=ApprovalClass.CONFIRM, read_only=True, path_action=True,
        owasp=("OWASP-LLM01:2025", "OWASP-LLM02:2025", "OWASP-ASVS4-V12"),
    ),
    "filesystem.cleanup_scan": ActionDescriptor(
        id="filesystem.cleanup_scan", effect=Effect.OBSERVE, risk="LOW", scope="path",
        approval=ApprovalClass.NONE, read_only=True, path_action=True,
        limits={"max_items": 5000, "max_bytes": 0},
        owasp=("OWASP-LLM06:2025", "OWASP-A01:2021", "OWASP-ASVS4-V12"),
    ),
    "filesystem.quarantine": ActionDescriptor(
        id="filesystem.quarantine", effect=Effect.STAGE, risk="HIGH", scope="path",
        approval=ApprovalClass.PLAN, read_only=False, path_action=True,
        inverse="filesystem.restore",
        limits={"max_items": 500, "max_bytes": 10_737_418_240},
        owasp=(
            "OWASP-LLM06:2025", "OWASP-A01:2021", "OWASP-A08:2021",
            "OWASP-ASVS4-V4", "OWASP-ASVS4-V12",
        ),
    ),
    "filesystem.restore": ActionDescriptor(
        id="filesystem.restore", effect=Effect.REVERSIBLE, risk="HIGH", scope="path",
        approval=ApprovalClass.PLAN, read_only=False, path_action=True,
        inverse="filesystem.quarantine",
        limits={"max_items": 500, "max_bytes": 10_737_418_240},
        owasp=(
            "OWASP-LLM06:2025", "OWASP-A01:2021", "OWASP-A08:2021",
            "OWASP-ASVS4-V4", "OWASP-ASVS4-V12",
        ),
    ),
}

#: Actions that are permanently outside every AI path.
FORBIDDEN_ACTIONS = frozenset(
    {
        "process.terminate", "process.kill", "process.signal",
        "filesystem.write", "filesystem.delete", "filesystem.rm",
        "filesystem.mkdir", "filesystem.chmod", "filesystem.chown",
        "filesystem.move", "filesystem.purge",
        "network.block", "network.open", "network.listen",
        "firewall.modify", "package.install", "package.remove",
        "service.start", "service.stop", "kernel.modify", "sysctl.write",
        "system.shutdown", "system.reboot", "shell.exec", "command.run", "exec",
    }
)

PLAN_ACTIONS = frozenset(
    name for name, descriptor in CATALOG.items()
    if descriptor.approval is ApprovalClass.PLAN
)


def descriptor_for(action: str) -> ActionDescriptor | None:
    return CATALOG.get(action)


def effect_for(action: str) -> Effect:
    descriptor = CATALOG.get(action)
    return descriptor.effect if descriptor else Effect.FORBIDDEN


def is_read_only(action: str) -> bool:
    descriptor = CATALOG.get(action)
    return bool(descriptor and descriptor.read_only)


def requires_plan(action: str) -> bool:
    return action in PLAN_ACTIONS


def assert_catalog_safe() -> None:
    """Fail at import time if the catalog contradicts the security model."""
    for name, descriptor in CATALOG.items():
        assert name == descriptor.id, f"catalog key/id mismatch: {name}"
        assert name not in FORBIDDEN_ACTIONS, f"{name} is both catalogued and forbidden"
        assert descriptor.effect is not Effect.FORBIDDEN, f"{name} claims FORBIDDEN"
        if descriptor.effect in (Effect.STAGE, Effect.REVERSIBLE):
            assert descriptor.inverse, f"{name} must declare an inverse"
            assert descriptor.inverse in CATALOG, (
                f"{name} declares an inverse that is not in the catalog"
            )
        assert descriptor.owasp, f"{name} has no OWASP tags"
        assert descriptor.risk in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}


assert_catalog_safe()

__all__ = [
    "CATALOG",
    "CATALOG_VERSION",
    "EXECUTOR_ACTIONS",
    "FORBIDDEN_ACTIONS",
    "PLAN_ACTIONS",
    "ActionDescriptor",
    "ApprovalClass",
    "Effect",
    "assert_catalog_safe",
    "descriptor_for",
    "effect_for",
    "is_read_only",
    "requires_plan",
]
