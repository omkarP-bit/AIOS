"""Security plane: capability manager, policy engine, security engine.

This package is T1. Nothing in here trusts the AI, and nothing in here reads
model output as an instruction.
"""

from aios.security.capabilities import (
    ACTION_RISK,
    DEFAULT_CAPABILITIES,
    RISK_DECISION,
    Capability,
    RiskClass,
    ScopeDimension,
    path_in_scope,
    pid_in_scope,
    risk_for,
    scope_dimension_for,
)
from aios.security.engine import (
    Decision,
    DenialReason,
    InMemoryLedger,
    LedgerRecord,
    PolicyDecision,
    RegoPolicyEngine,
    SecurityEngine,
    Verdict,
    make_ai_request,
    new_action_id,
)
from aios.security.manager import CapabilityCheck, CapabilityManager
from aios.security.opa import OpaPolicyEngine
from aios.security.policy_input import action_target, build_policy_input

__all__ = [
    "ACTION_RISK",
    "Capability",
    "CapabilityCheck",
    "CapabilityManager",
    "DEFAULT_CAPABILITIES",
    "Decision",
    "DenialReason",
    "InMemoryLedger",
    "LedgerRecord",
    "OpaPolicyEngine",
    "PolicyDecision",
    "RISK_DECISION",
    "RegoPolicyEngine",
    "RiskClass",
    "ScopeDimension",
    "SecurityEngine",
    "Verdict",
    "action_target",
    "build_policy_input",
    "make_ai_request",
    "new_action_id",
    "path_in_scope",
    "pid_in_scope",
    "risk_for",
    "scope_dimension_for",
]
