// Package engine is the security boundary: the AI proposes, the engine
// decides, nothing else executes.
//
// Order is fixed: protocol checks, structural checks, capability grant,
// Rego policy, then (only from AUTHORIZED) the gateway or executor.
package engine

import (
	"fmt"
	"time"

	"aios/internal/actions"
	"aios/internal/capability"
	"aios/internal/catalog"
	"aios/internal/gateway"
	"aios/internal/ledger"
	"aios/internal/model"
	"aios/internal/plan"
	"aios/internal/policy"
	"aios/internal/protocol"
)

// DenialReason is a closed, countable reason.
type DenialReason string

const (
	NotInProtocol        DenialReason = "not_in_protocol"
	ForbiddenAction      DenialReason = "forbidden_action"
	InvalidParams        DenialReason = "invalid_params"
	ScopeMismatch        DenialReason = "scope_mismatch"
	CapabilityMissing    DenialReason = "capability_missing"
	CapabilityRevoked    DenialReason = "capability_revoked"
	CapabilityExpired    DenialReason = "capability_expired"
	RiskTooHigh          DenialReason = "risk_too_high"
	PolicyDeny           DenialReason = "policy_deny"
	PolicyUnavailable    DenialReason = "policy_unavailable"
	GatewayRefused       DenialReason = "gateway_refused"
	GatewayError         DenialReason = "gateway_error"
	ConfirmationRequired DenialReason = "confirmation_required"
	PlanRequired         DenialReason = "plan_required"
	ApprovalInvalid      DenialReason = "approval_invalid"
	ApprovalExpired      DenialReason = "approval_expired"
	PlanMismatch         DenialReason = "plan_mismatch"
	TargetChanged        DenialReason = "target_changed"
	ExecutorRefused      DenialReason = "executor_refused"
	LimitExceeded        DenialReason = "limit_exceeded"
	PlanReplayed         DenialReason = "plan_replayed"
	CrossDevice          DenialReason = "cross_device"
	NotPermitted         DenialReason = "not_permitted"
	ZombieNotKillable    DenialReason = "zombie_not_killable"
	BackendUnavailable   DenialReason = "backend_unavailable"
	InternalError        DenialReason = "internal_error"
)

// ActionResult is the successful execution payload.
type ActionResult struct {
	ActionID    string  `json:"action_id"`
	State       string  `json:"state"`
	Success     bool    `json:"success"`
	Data        any     `json:"data"`
	Source      string  `json:"source"`
	TrustDomain string  `json:"trust_domain"`
	DurationMS  float64 `json:"duration_ms"`
}

// Verdict is the complete outcome for one action.
type Verdict struct {
	ActionID     string            `json:"action_id"`
	Action       string            `json:"action"`
	State        protocol.State    `json:"state"`
	Decision     policy.Decision   `json:"decision"`
	Risk         string            `json:"risk"`
	Reason       string            `json:"reason"`
	DenialReason *DenialReason     `json:"denial_reason"`
	Capability   *capability.Check `json:"capability"`
	Policy       *policy.Result    `json:"policy"`
	Result       *ActionResult     `json:"result"`
	Observation  *gateway.Envelope `json:"observation"`
	Executed     bool              `json:"executed"`
	At           model.Timestamp   `json:"at"`
	DurationMS   float64           `json:"duration_ms"`
}

// Engine validates, authorizes, and executes.
type Engine struct {
	Gateway      *gateway.Gateway
	Executor     actions.Executor
	Capabilities *capability.Manager
	Policy       policy.Engine
	Ledger       *ledger.Ledger
	LedgerErrors int
}

// New builds an engine with deny-by-default capabilities and the Rego policy.
func New(gw *gateway.Gateway, executor actions.Executor, capabilities *capability.Manager, policyEngine policy.Engine, audit *ledger.Ledger) *Engine {
	if capabilities == nil {
		capabilities = capability.NewManager()
	}
	if policyEngine == nil {
		policyEngine = policy.NewRego("", "", 0)
	}
	if audit == nil {
		audit, _ = ledger.New("")
	}
	return &Engine{
		Gateway: gw, Executor: executor, Capabilities: capabilities,
		Policy: policyEngine, Ledger: audit,
	}
}

// Authorize runs every check except execution.
func (e *Engine) Authorize(req *protocol.Request, p *plan.Plan, grant *plan.Grant) Verdict {
	return e.pipeline(req, false, p, grant)
}

// Process validates, authorizes, and executes.
func (e *Engine) Process(req *protocol.Request, p *plan.Plan, grant *plan.Grant) Verdict {
	return e.pipeline(req, true, p, grant)
}

func (e *Engine) pipeline(req *protocol.Request, execute bool, p *plan.Plan, grant *plan.Grant) Verdict {
	started := time.Now()
	name := req.ActionName()
	state := protocol.StateProposed
	risk := string(catalog.RiskFor(name))

	if req.Trust.Trusted() {
		return e.deny(req, state, policy.Deny, risk, PolicyDeny,
			"agent proposals may not claim a trusted origin", started, nil, nil)
	}
	if catalog.Forbidden[name] {
		return e.deny(req, state, policy.Deny, risk, ForbiddenAction,
			name+" is forbidden", started, nil, nil)
	}
	servedByGateway := e.Gateway != nil && e.Gateway.Supports(name)
	servedByExecutor := e.Executor != nil && catalog.ExecutorActions[name]
	if !servedByGateway && !servedByExecutor {
		return e.deny(req, state, policy.Deny, risk, NotInProtocol,
			name+" is not in the execution whitelist", started, nil, nil)
	}
	if req.Trust == protocol.TrustT4 && catalog.PathParam(name) {
		return e.deny(req, state, policy.Deny, risk, PolicyDeny,
			"external-origin proposals may not request filesystem paths", started, nil, nil)
	}
	if err := req.CheckScopeConsistency(); err != nil {
		return e.deny(req, state, policy.Deny, risk, ScopeMismatch, err.Error(), started, nil, nil)
	}
	if !catalog.IsReadOnly(name) && req.Origin != protocol.OriginUser {
		return e.deny(req, state, policy.Deny, risk, PolicyDeny,
			"mutations require a trusted-channel operator instruction", started, nil, nil)
	}

	state = e.transition(req, state, protocol.StateValidated, risk, policy.Allow,
		"schema and structure valid", nil, nil, nil, nil)

	targets := requestTargets(req, p)
	target := ""
	if len(targets) > 0 {
		target = targets[0]
	}
	check, deniedCheck := e.checkCapabilities(req, targets)
	decision := policy.Deny
	if check.Allowed {
		decision = policy.Allow
	}
	e.log(req, state, risk, decision, check.Reason, &check, nil, nil, &target)
	if !check.Allowed {
		return e.verdict(req, protocol.StateValidated, policy.Deny, risk, check.Reason,
			classifyCapabilityDenial(e.Capabilities, req.AgentID, name, deniedCheck), &check, nil, started)
	}

	policyStarted := time.Now()
	result := e.Policy.Evaluate(req, &check, p, grant)
	result.LatencyMS = float64(time.Since(policyStarted)) / float64(time.Millisecond)
	e.log(req, protocol.StateValidated, risk, result.Decision, result.Reason,
		&check, nil, &result.Source, &target)
	if result.Decision == policy.Deny {
		denial := PolicyDeny
		if result.Unavailable() {
			denial = PolicyUnavailable
		}
		return e.verdict(req, protocol.StateValidated, policy.Deny, risk, result.Reason,
			denial, &check, &result, started)
	}
	if result.Decision == policy.Confirm {
		state = e.transition(req, state, protocol.StateAwaitingConfirmation, risk,
			policy.Confirm, result.Reason, &check, nil, &result.Source, &target)
		return e.verdict(req, state, policy.Confirm, risk, result.Reason,
			"", &check, &result, started)
	}

	state = e.transition(req, protocol.StateValidated, protocol.StateAuthorized, risk,
		policy.Allow, result.Reason, &check, nil, &result.Source, &target)

	if !execute {
		return e.verdict(req, state, policy.Allow, risk, result.Reason, "",
			&check, &result, started)
	}

	if servedByExecutor {
		if e.Executor == nil || p == nil || grant == nil || !catalog.RequiresPlan(name) {
			return e.verdict(req, state, policy.Deny, risk,
				"mutation requires an approved plan", PlanRequired,
				&check, &result, started)
		}
		if err := grant.ValidFor(*p, time.Now()); err != nil {
			denial := ApprovalInvalid
			if err.Error() == "approval has expired" {
				denial = ApprovalExpired
			}
			return e.verdict(req, state, policy.Deny, risk, err.Error(),
				denial, &check, &result, started)
		}
		mutationStarted := time.Now()
		step, err := e.Executor.Execute(req, *p, *grant)
		if err != nil {
			denial := ExecutorRefused
			if execErr, ok := err.(actions.ExecutorError); ok {
				denial = mapExecutorReason(execErr.Reason)
			}
			return e.verdict(req, state, policy.Deny, risk, err.Error(),
				denial, &check, &result, started)
		}
		durationMS := float64(time.Since(mutationStarted)) / float64(time.Millisecond)
		e.log(req, protocol.StateExecuted, risk, policy.Allow, name+" applied",
			&check, &durationMS, nil, &target)
		e.transition(req, protocol.StateExecuted, protocol.StateCompleted, risk,
			policy.Allow, "mutation completed", &check, &durationMS, nil, &target)
		actionResult := &ActionResult{
			ActionID: req.ActionID, State: string(protocol.StateCompleted),
			Success: true, Data: step, Source: "executor:" + name,
			TrustDomain: "T1", DurationMS: durationMS,
		}
		return Verdict{
			ActionID: req.ActionID, Action: name, State: protocol.StateCompleted,
			Decision: policy.Allow, Risk: risk, Reason: result.Reason,
			Capability: &check, Policy: &result, Result: actionResult,
			Executed: true, At: now(), DurationMS: ms(started),
		}
	}

	observation, err := e.Gateway.Execute(req)
	if err != nil {
		denial := GatewayRefused
		if _, ok := err.(gateway.ActionNotPermitted); ok {
			denial = GatewayRefused
		} else if _, ok := err.(gateway.PreconditionFailed); !ok {
			denial = GatewayError
		}
		return e.verdict(req, state, policy.Deny, risk, err.Error(),
			denial, &check, &result, started)
	}
	durationMS := float64(time.Since(started)) / float64(time.Millisecond)
	e.log(req, protocol.StateExecuted, risk, policy.Allow, "executed",
		&check, &durationMS, nil, &target)
	e.transition(req, protocol.StateExecuted, protocol.StateObserved, risk, policy.Allow,
		fmt.Sprintf("observation returned from %s (%s)", observation.Source, observation.TrustDomain),
		&check, nil, nil, &target)
	e.transition(req, protocol.StateObserved, protocol.StateCompleted, risk, policy.Allow,
		"read-only action completed", &check, &durationMS, nil, &target)
	actionResult := &ActionResult{
		ActionID: req.ActionID, State: string(protocol.StateCompleted), Success: true,
		Source: observation.Source, TrustDomain: observation.TrustDomain,
		DurationMS: durationMS,
	}
	return Verdict{
		ActionID: req.ActionID, Action: name, State: protocol.StateCompleted,
		Decision: policy.Allow, Risk: risk, Reason: result.Reason,
		Capability: &check, Policy: &result, Result: actionResult,
		Observation: observation, Executed: true, At: now(), DurationMS: ms(started),
	}
}

func (e *Engine) transition(req *protocol.Request, from, to protocol.State, risk string, decision policy.Decision, reason string, check *capability.Check, durationMS *float64, policySource, target *string) protocol.State {
	_ = protocol.AssertTransition(from, to)
	e.log(req, to, risk, decision, reason, check, durationMS, policySource, target)
	return to
}

func (e *Engine) log(req *protocol.Request, state protocol.State, risk string, decision policy.Decision, reason string, check *capability.Check, durationMS *float64, policySource, target *string) {
	entry := ledger.Entry{
		ActionID: req.ActionID, SessionID: req.SessionID, AgentID: req.AgentID,
		Action: req.ActionName(), State: string(state), Risk: risk,
		Decision: string(decision), Reason: reason,
		PolicySource: policySource, Target: target, DurationMS: durationMS,
		At: now(),
	}
	if check != nil {
		matched := check.MatchedCapability
		capReason := check.Reason
		entry.Capability = &matched
		entry.CapabilityReason = &capReason
	}
	if err := e.Ledger.Record(entry); err != nil {
		e.LedgerErrors++
	}
}

func (e *Engine) deny(req *protocol.Request, state protocol.State, decision policy.Decision, risk string, denial DenialReason, reason string, started time.Time, check *capability.Check, result *policy.Result) Verdict {
	detail := string(denial)
	entry := ledger.Entry{
		ActionID: req.ActionID, SessionID: req.SessionID, AgentID: req.AgentID,
		Action: req.ActionName(), State: string(state), Risk: risk,
		Decision: string(decision), Reason: reason, Detail: &detail, At: now(),
	}
	if err := e.Ledger.Record(entry); err != nil {
		e.LedgerErrors++
	}
	return e.verdict(req, state, decision, risk, reason, denial, check, result, started)
}

func (e *Engine) verdict(req *protocol.Request, state protocol.State, decision policy.Decision, risk, reason string, denial DenialReason, check *capability.Check, result *policy.Result, started time.Time) Verdict {
	terminal := state
	var denialPtr *DenialReason
	if denial != "" {
		terminal = protocol.StateDenied
		_ = protocol.AssertTransition(state, terminal)
		detail := string(denial)
		entry := ledger.Entry{
			ActionID: req.ActionID, SessionID: req.SessionID, AgentID: req.AgentID,
			Action: req.ActionName(), State: string(terminal), Risk: risk,
			Decision: string(decision), Reason: reason, Detail: &detail,
			DenialReason: &detail, At: now(),
		}
		if check != nil {
			matched := check.MatchedCapability
			entry.Capability = &matched
		}
		if err := e.Ledger.Record(entry); err != nil {
			e.LedgerErrors++
		}
		denialPtr = &denial
	}
	return Verdict{
		ActionID: req.ActionID, Action: req.ActionName(), State: terminal,
		Decision: decision, Risk: risk, Reason: reason, DenialReason: denialPtr,
		Capability: check, Policy: result, At: now(), DurationMS: ms(started),
	}
}

// requestTargets returns every resource a request may touch. A plan-only
// mutation has no path in its params, so its targets come from the engine-built
// plan instead. An empty target is returned deliberately: capability checks
// deny PATH actions without a resolved target.
func requestTargets(req *protocol.Request, p *plan.Plan) []string {
	if target := req.Target(); target != "" {
		return []string{target}
	}
	if p == nil || !catalog.PathParam(req.ActionName()) {
		return []string{""}
	}
	out := []string{}
	seen := map[string]bool{}
	for _, step := range p.Steps {
		if !catalog.PathParam(step.Action) {
			continue
		}
		for _, target := range []string{step.Path, step.Target} {
			if target == "" || seen[target] {
				continue
			}
			seen[target] = true
			out = append(out, target)
		}
	}
	if len(out) == 0 {
		return []string{""}
	}
	return out
}

// checkCapabilities requires a grant for every target. One out-of-scope target
// is enough to deny the whole request.
func (e *Engine) checkCapabilities(req *protocol.Request, targets []string) (capability.Check, capability.Check) {
	merged := capability.Check{
		AgentID: req.AgentID, Action: req.ActionName(), Allowed: true,
		Reason: "capability granted", Dimension: catalog.ScopeDimensionFor(req.ActionName()),
		Risk: string(catalog.RiskFor(req.ActionName())),
	}
	denied := merged
	for index, target := range targets {
		check := e.Capabilities.Check(req.AgentID, req.ActionName(), target, time.Now())
		if index == 0 {
			merged.Target = target
			merged.MatchedCapability = check.MatchedCapability
		}
		if check.Allowed {
			continue
		}
		merged.Allowed = false
		merged.Reason = check.Reason
		if denied.Reason == "capability granted" {
			denied = check
		}
	}
	return merged, denied
}

func classifyCapabilityDenial(manager *capability.Manager, agentID, action string, check capability.Check) DenialReason {
	if check.Expired {
		return CapabilityExpired
	}
	if manager.IsRevoked(agentID, action) {
		return CapabilityRevoked
	}
	if !manager.Has(agentID, action) {
		return CapabilityMissing
	}
	return ScopeMismatch
}

func mapExecutorReason(reason string) DenialReason {
	switch reason {
	case "target_missing", "target_changed":
		return TargetChanged
	case "scope_mismatch":
		return ScopeMismatch
	case "approval_invalid":
		return ApprovalInvalid
	case "approval_expired":
		return ApprovalExpired
	case "plan_replayed":
		return PlanReplayed
	case "cross_device":
		return CrossDevice
	case "limit_exceeded":
		return LimitExceeded
	case "not_permitted":
		return NotPermitted
	case "zombie_not_killable":
		return ZombieNotKillable
	case "network_backend_unavailable":
		return BackendUnavailable
	case "executor_unavailable":
		return ExecutorRefused
	default:
		return ExecutorRefused
	}
}

func now() model.Timestamp {
	return model.Timestamp{Time: time.Now().UTC().Truncate(time.Microsecond)}
}

func ms(started time.Time) float64 {
	return float64(time.Since(started)) / float64(time.Millisecond)
}
