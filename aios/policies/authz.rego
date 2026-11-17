package aios.authz

import future.keywords.if
import future.keywords.in

default decision := {
  "decision": "DENY",
  "reason": "deny by default: no policy matched",
  "policy_id": "aios.authz.default",
  "owasp_tags": [],
}

meta := data.aios.allowed_actions[input.action]

effect := object.get(meta, "effect", "OBSERVE") if { meta }
effect := "FORBIDDEN" if { not meta }

approval_class := object.get(meta, "approval", "none") if { meta }
approval_class := "none" if { not meta }

owasp_tags := object.get(meta, "owasp", []) if { meta }
owasp_tags := [] if { not meta }

deny_reason := "forbidden_action" if {
  input.action in data.aios.forbidden_actions
} else := "unknown_action" if {
  not meta
} else := "unknown_agent" if {
  not input.agent_id in data.aios.allowed_agents
} else := "trusted_origin_claimed" if {
  input.trust_domain in {"T0", "T1", "T2"}
} else := "capability_missing" if {
  not input.capability.allowed
} else := "scope_mismatch" if {
  meta.path_action
  not input.capability.target_in_scope
} else := "untrusted_origin" if {
  input.trust_domain == "T4"
  meta.path_action
} else := "risk_mismatch" if {
  input.risk != meta.risk
} else := "effect_forbidden" if {
  effect == "FORBIDDEN"
} else := "risk_ceiling" if {
  input.risk == "CRITICAL"
} else := "approval_required" if {
  approval_class == "plan"
  not input.approval.valid
} else := "approval_plan_mismatch" if {
  approval_class == "plan"
  input.approval.plan_hash != input.plan.hash
} else := "approval_expired" if {
  approval_class == "plan"
  input.approval.expires_at_ns < time.now_ns()
} else := "plan_contains_forbidden_step" if {
  input.plan.forbidden_step
} else := "limits_exceeded" if {
  input.plan.limits.items_ok == false
} else := "limits_exceeded" if {
  input.plan.limits.bytes_ok == false
} else := "high_risk_unapproved" if {
  input.risk == "HIGH"
  approval_class != "plan"
} else := "invalid_risk" if {
  not input.risk in {"LOW", "MEDIUM", "HIGH"}
} else := ""

decision := {
  "decision": "DENY",
  "reason": deny_reason,
  "policy_id": "aios.authz.deny",
  "owasp_tags": owasp_tags,
} if {
  deny_reason != ""
}

decision := {
  "decision": "CONFIRM",
  "reason": "human confirmation required",
  "policy_id": "aios.authz.confirm",
  "owasp_tags": owasp_tags,
} if {
  deny_reason == ""
  input.risk == "MEDIUM"
  not input.operator_confirmed
}

decision := {
  "decision": "ALLOW",
  "reason": "operator confirmed medium-risk action",
  "policy_id": "aios.authz.allow-confirmed",
  "owasp_tags": owasp_tags,
} if {
  deny_reason == ""
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
  deny_reason == ""
  input.risk == "LOW"
  meta.read_only
  approval_class != "plan"
}

decision := {
  "decision": "ALLOW",
  "reason": "approved plan within policy limits",
  "policy_id": "aios.authz.allow-plan",
  "owasp_tags": owasp_tags,
} if {
  deny_reason == ""
  approval_class == "plan"
  input.approval.valid
  input.risk == "HIGH"
}
