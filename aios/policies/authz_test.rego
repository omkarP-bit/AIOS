package aios.authz

import future.keywords.if

low_input := {
  "action": "process.list",
  "agent_id": "local-agent",
  "session_id": "s",
  "risk": "LOW",
  "trust_domain": "T3",
  "capability": {"allowed": true, "matched": "process.list", "target_in_scope": true},
}

test_low_risk_is_allowed if {
  decision.decision == "ALLOW" with input as low_input
}

medium_input := object.union(low_input, {
  "action": "filesystem.read",
  "risk": "MEDIUM",
  "capability": {"allowed": true, "matched": "filesystem.read:/tmp/*", "target_in_scope": true},
})

test_medium_risk_requires_confirmation if {
  decision.decision == "CONFIRM" with input as medium_input
}

test_confirmed_medium_risk_is_allowed if {
  confirmed := object.union(medium_input, {"operator_confirmed": true})
  decision.decision == "ALLOW" with input as confirmed
  decision.policy_id == "aios.authz.allow-confirmed" with input as confirmed
}

test_confirmed_low_risk_keeps_the_low_rule if {
  confirmed := object.union(low_input, {"operator_confirmed": true})
  decision.decision == "ALLOW" with input as confirmed
  decision.policy_id == "aios.authz.allow-low" with input as confirmed
}

test_confirmation_cannot_approve_a_plan_action if {
  confirmed := object.union(object.remove(high_input, ["approval"]), {"operator_confirmed": true})
  decision.decision == "DENY" with input as confirmed
  decision.reason == "approval_required" with input as confirmed
}

test_forbidden_action_is_denied if {
  decision.decision == "DENY" with input as object.union(low_input, {"action": "process.terminate"})
}

test_unknown_action_is_denied if {
  decision.decision == "DENY" with input as object.union(low_input, {"action": "not.real"})
}

test_missing_capability_is_denied if {
  decision.decision == "DENY" with input as object.union(low_input, {
    "capability": {"allowed": false, "target_in_scope": false},
  })
}

test_untrusted_path_action_is_denied if {
  decision.decision == "DENY" with input as object.union(low_input, {
    "action": "filesystem.list",
    "trust_domain": "T4",
  })
}

test_trusted_origin_is_denied if {
  decision.decision == "DENY" with input as object.union(low_input, {"trust_domain": "T0"})
}

test_unknown_agent_is_denied if {
  decision.decision == "DENY" with input as object.union(low_input, {"agent_id": "other"})
}

test_scope_mismatch_is_denied if {
  decision.decision == "DENY" with input as object.union(low_input, {
    "action": "filesystem.list",
    "capability": {"allowed": true, "target_in_scope": false},
  })
}

test_risk_mismatch_is_denied if {
  decision.decision == "DENY" with input as object.union(low_input, {"risk": "CRITICAL"})
}

# ---------------------------------------------------------------- plan actions

high_input := {
  "action": "filesystem.quarantine",
  "agent_id": "local-agent",
  "session_id": "s",
  "risk": "HIGH",
  "trust_domain": "T3",
  "capability": {"allowed": true, "matched": "filesystem.quarantine", "target_in_scope": true},
  "plan": {
    "id": "plan-1",
    "hash": "sha256:abc",
    "steps": 1,
    "forbidden_step": false,
    "limits": {"items_ok": true, "bytes_ok": true},
  },
  "approval": {"valid": true, "plan_hash": "sha256:abc", "expires_at_ns": 9999999999999999999},
}

test_approved_plan_is_allowed if {
  decision.decision == "ALLOW" with input as high_input
}

test_approved_restore_is_allowed if {
  decision.decision == "ALLOW" with input as object.union(high_input, {
    "action": "filesystem.restore",
  })
}

test_plan_action_without_approval_is_denied if {
  without := object.remove(high_input, ["approval"])
  decision.decision == "DENY" with input as without
  decision.reason == "approval_required" with input as without
}

test_plan_action_with_invalid_approval_is_denied if {
  decision.decision == "DENY" with input as object.union(high_input, {
    "approval": {"valid": false},
  })
}

test_approval_for_another_plan_is_denied if {
  decision.decision == "DENY" with input as object.union(high_input, {
    "approval": {"valid": true, "plan_hash": "sha256:other", "expires_at_ns": 9999999999999999999},
  })
  decision.reason == "approval_plan_mismatch" with input as object.union(high_input, {
    "approval": {"valid": true, "plan_hash": "sha256:other", "expires_at_ns": 9999999999999999999},
  })
}

test_expired_approval_is_denied if {
  decision.decision == "DENY" with input as object.union(high_input, {
    "approval": {"valid": true, "plan_hash": "sha256:abc", "expires_at_ns": 1},
  })
  decision.reason == "approval_expired" with input as object.union(high_input, {
    "approval": {"valid": true, "plan_hash": "sha256:abc", "expires_at_ns": 1},
  })
}

test_plan_with_a_forbidden_step_is_denied if {
  decision.decision == "DENY" with input as object.union(high_input, {
    "plan": object.union(high_input.plan, {"forbidden_step": true}),
  })
  decision.reason == "plan_contains_forbidden_step" with input as object.union(high_input, {
    "plan": object.union(high_input.plan, {"forbidden_step": true}),
  })
}

test_plan_over_the_item_limit_is_denied if {
  decision.decision == "DENY" with input as object.union(high_input, {
    "plan": object.union(high_input.plan, {"limits": {"items_ok": false, "bytes_ok": true}}),
  })
  decision.reason == "limits_exceeded" with input as object.union(high_input, {
    "plan": object.union(high_input.plan, {"limits": {"items_ok": false, "bytes_ok": true}}),
  })
}

test_plan_over_the_byte_limit_is_denied if {
  decision.decision == "DENY" with input as object.union(high_input, {
    "plan": object.union(high_input.plan, {"limits": {"items_ok": true, "bytes_ok": false}}),
  })
  decision.reason == "limits_exceeded" with input as object.union(high_input, {
    "plan": object.union(high_input.plan, {"limits": {"items_ok": true, "bytes_ok": false}}),
  })
}

test_plan_action_with_downgraded_risk_is_denied if {
  decision.decision == "DENY" with input as object.union(high_input, {"risk": "LOW"})
  decision.reason == "risk_mismatch" with input as object.union(high_input, {"risk": "LOW"})
}
