package aios.authz

import future.keywords.if
import future.keywords.in

# Fail closed. Every decision below is a complete, closed record; an OPA
# failure, timeout, or malformed input is handled by the Go caller as DENY.
default decision := {
  "decision": "DENY",
  "reason": "deny by default: no policy matched",
  "policy_id": "aios.authz.default",
  "owasp_tags": [],
}

meta := data.aios.allowed_actions[input.action]

allowed_origins := {
  "kernel", "sysfs", "gateway", "security", "policy",
  "ai", "user", "external", "tool",
}

effect := object.get(meta, "effect", "OBSERVE") if { meta }
effect := "FORBIDDEN" if { not meta }

approval_class := object.get(meta, "approval", "none") if { meta }
approval_class := "none" if { not meta }

owasp_tags := object.get(meta, "owasp", []) if { meta }
owasp_tags := [] if { not meta }

# Explicit veto set. Adding a rule can only add a denial; allow rules require
# count(deny) == 0. deny_reason below is an ordered projection of this set, so
# a proposal with several defects always reports the same highest-priority
# reason. Reasons are stable identifiers, never free text from the request.
deny[reason] {
  input.action in data.aios.forbidden_actions
  reason := "forbidden_action"
}

deny[reason] {
  not meta
  reason := "unknown_action"
}

deny[reason] {
  not input.agent_id in data.aios.allowed_agents
  reason := "unknown_agent"
}

deny[reason] {
  not input.origin in allowed_origins
  reason := "invalid_origin"
}

deny[reason] {
  input.trust_domain in {"T0", "T1", "T2"}
  reason := "trusted_origin_claimed"
}

deny[reason] {
  not input.capability.allowed
  reason := "capability_missing"
}

deny[reason] {
  meta.path_action
  not input.capability.target_in_scope
  reason := "scope_mismatch"
}

deny[reason] {
  input.trust_domain == "T4"
  meta.path_action
  reason := "untrusted_origin"
}

deny[reason] {
  input.read_only == false
  input.origin != "user"
  reason := "untrusted_mutation_origin"
}

deny[reason] {
  input.read_only == false
  not input.params.has_target
  not input.params.plan_id_present
  reason := "mutation_target_missing"
}

deny[reason] {
  input.risk != meta.risk
  reason := "risk_mismatch"
}

deny[reason] {
  effect == "FORBIDDEN"
  reason := "effect_forbidden"
}

deny[reason] {
  input.risk == "CRITICAL"
  reason := "risk_ceiling"
}

deny[reason] {
  approval_class == "plan"
  not input.approval.valid
  reason := "approval_required"
}

deny[reason] {
  approval_class == "plan"
  input.approval.plan_hash != input.plan.hash
  reason := "approval_plan_mismatch"
}

deny[reason] {
  approval_class == "plan"
  input.approval.expires_at_ns < time.now_ns()
  reason := "approval_expired"
}

deny[reason] {
  input.plan.forbidden_step
  reason := "plan_contains_forbidden_step"
}

deny[reason] {
  input.plan.limits.items_ok == false
  reason := "limits_exceeded"
}

deny[reason] {
  input.plan.limits.bytes_ok == false
  reason := "limits_exceeded"
}

deny[reason] {
  input.risk == "HIGH"
  approval_class != "plan"
  reason := "high_risk_unapproved"
}

deny[reason] {
  not input.risk in {"LOW", "MEDIUM", "HIGH"}
  reason := "invalid_risk"
}

# Deterministic priority. The first matching deny rule wins; if none matches,
# deny_reason is empty and an allow rule may decide.
deny_reason := "forbidden_action" if { deny["forbidden_action"] }
else := "unknown_action" if { deny["unknown_action"] }
else := "unknown_agent" if { deny["unknown_agent"] }
else := "invalid_origin" if { deny["invalid_origin"] }
else := "trusted_origin_claimed" if { deny["trusted_origin_claimed"] }
else := "capability_missing" if { deny["capability_missing"] }
else := "scope_mismatch" if { deny["scope_mismatch"] }
else := "untrusted_origin" if { deny["untrusted_origin"] }
else := "untrusted_mutation_origin" if { deny["untrusted_mutation_origin"] }
else := "mutation_target_missing" if { deny["mutation_target_missing"] }
else := "risk_mismatch" if { deny["risk_mismatch"] }
else := "effect_forbidden" if { deny["effect_forbidden"] }
else := "risk_ceiling" if { deny["risk_ceiling"] }
else := "approval_required" if { deny["approval_required"] }
else := "approval_plan_mismatch" if { deny["approval_plan_mismatch"] }
else := "approval_expired" if { deny["approval_expired"] }
else := "plan_contains_forbidden_step" if { deny["plan_contains_forbidden_step"] }
else := "limits_exceeded" if { deny["limits_exceeded"] }
else := "high_risk_unapproved" if { deny["high_risk_unapproved"] }
else := "invalid_risk" if { deny["invalid_risk"] }
else := "" if { count(deny) == 0 }

decision := {
  "decision": "DENY",
  "reason": deny_reason,
  "policy_id": "aios.authz.deny",
  "owasp_tags": owasp_tags,
} if {
  count(deny) > 0
}

# A MEDIUM action needs a human only when it is not already bound to an
# approved plan. Plan actions can never be approved by this generic confirm
# path; their approval is the signed, hash-bound plan token.
decision := {
  "decision": "CONFIRM",
  "reason": "human confirmation required",
  "policy_id": "aios.authz.confirm",
  "owasp_tags": owasp_tags,
} if {
  count(deny) == 0
  input.risk == "MEDIUM"
  approval_class != "plan"
  not input.operator_confirmed
}

decision := {
  "decision": "ALLOW",
  "reason": "operator confirmed medium-risk action",
  "policy_id": "aios.authz.allow-confirmed",
  "owasp_tags": owasp_tags,
} if {
  count(deny) == 0
  input.risk == "MEDIUM"
  approval_class == "confirm"
  input.operator_confirmed == true
}

decision := {
  "decision": "ALLOW",
  "reason": "low-risk read-only action",
  "policy_id": "aios.authz.allow-low",
  "owasp_tags": owasp_tags,
} if {
  count(deny) == 0
  input.risk == "LOW"
  meta.read_only
  approval_class != "plan"
}

# Both HIGH (quarantine/restore/signal) and MEDIUM (trash) reversible plan
# actions are allowed only after an exact plan approval has been verified.
# OPA cannot widen the local floor: Go applies the stricter decision.
decision := {
  "decision": "ALLOW",
  "reason": "approved plan within policy limits",
  "policy_id": "aios.authz.allow-plan",
  "owasp_tags": owasp_tags,
} if {
  count(deny) == 0
  approval_class == "plan"
  input.approval.valid
  input.risk in {"HIGH", "MEDIUM"}
}
