"""Typed action catalog and plan/approval machinery."""

from aios.actions.catalog import (
    CATALOG,
    EXECUTOR_ACTIONS,
    FORBIDDEN_ACTIONS,
    PLAN_ACTIONS,
    ActionDescriptor,
    ApprovalClass,
    Effect,
    descriptor_for,
    effect_for,
    is_read_only,
    requires_plan,
)

__all__ = [
    "CATALOG",
    "EXECUTOR_ACTIONS",
    "FORBIDDEN_ACTIONS",
    "PLAN_ACTIONS",
    "ActionDescriptor",
    "ApprovalClass",
    "Effect",
    "descriptor_for",
    "effect_for",
    "is_read_only",
    "requires_plan",
]
