"""Normalized input document for the policy engine."""

from __future__ import annotations

from typing import Any

from aios.actions.catalog import descriptor_for, effect_for, is_read_only
from aios.models.actions import ActionRequest
from aios.security.capabilities import (
    PATH_PARAM_ACTIONS,
    RiskClass,
    ScopeDimension,
    scope_dimension_for,
)


def _policy_doc(value: Any) -> dict[str, Any]:
    if value is None:
        return {}
    if isinstance(value, dict):
        return value
    to_doc = getattr(value, "to_policy_doc", None)
    if callable(to_doc):
        return to_doc()
    return {}


def action_target(request: ActionRequest) -> str | None:
    dimension = scope_dimension_for(request.action_name)
    params = request.typed_params
    if dimension is ScopeDimension.PID:
        return str(params.pid)
    if dimension is ScopeDimension.PATH:
        return params.path
    if dimension is ScopeDimension.UID:
        return str(getattr(params, "uid", ""))
    return None


def build_policy_input(
    request: ActionRequest,
    risk: RiskClass,
    capability: Any | None = None,
    *,
    plan: Any | None = None,
    approval: Any | None = None,
) -> dict[str, Any]:
    dimension = scope_dimension_for(request.action_name)
    target = action_target(request)
    if dimension is ScopeDimension.NONE:
        target_in_scope = True
    else:
        target_in_scope = bool(capability and capability.allowed)

    descriptor = descriptor_for(request.action_name)
    capability_doc = {
        "allowed": bool(capability and capability.allowed),
        "matched": capability.matched_capability if capability else None,
        "target_in_scope": target_in_scope,
    }

    return {
        "action": request.action_name,
        "params": request.params,
        "target": target,
        "risk": risk.value,
        "effect": effect_for(request.action_name).value,
        "read_only": is_read_only(request.action_name),
        "path_action": request.action_name in PATH_PARAM_ACTIONS,
        "approval_class": descriptor.approval.value if descriptor else "none",
        "agent_id": request.agent_id,
        "session_id": request.session_id,
        "trust_domain": request.trust_domain.value,
        "capability": capability_doc,
        "requested_scope": request.requested_scope,
        "intent": request.intent,
        "plan": _policy_doc(plan),
        "approval": _policy_doc(approval),
    }


__all__ = ["action_target", "build_policy_input"]
