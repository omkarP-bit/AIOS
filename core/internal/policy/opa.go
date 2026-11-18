// Package policy transports an input document to OPA and parses the decision.
// The rules themselves live in aios/policies/authz.rego. If OPA cannot run,
// the result is DENY: policy is never inferred from a failure.
package policy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"time"

	"aios/internal/capability"
	"aios/internal/catalog"
	"aios/internal/config"
	"aios/internal/plan"
	"aios/internal/protocol"
)

// Decision is the closed policy outcome.
type Decision string

const (
	Allow   Decision = "ALLOW"
	Confirm Decision = "CONFIRM"
	Deny    Decision = "DENY"
)

// Result is one deterministic policy outcome.
type Result struct {
	Decision  Decision       `json:"decision"`
	Reason    string         `json:"reason"`
	Risk      string         `json:"risk"`
	Source    string         `json:"source"`
	PolicyID  *string        `json:"policy_id"`
	InputDoc  map[string]any `json:"input_doc"`
	LatencyMS float64        `json:"latency_ms"`
}

// Unavailable reports whether the engine could not evaluate the policy.
func (r Result) Unavailable() bool {
	return len(r.Source) >= 12 && r.Source[len(r.Source)-12:] == ":unavailable"
}

// Engine is the policy decision point.
type Engine interface {
	Evaluate(req *protocol.Request, check *capability.Check, p *plan.Plan, grant *plan.Grant) Result
}

// Doc builds the read-only document Rego receives. Everything here is derived
// from validated structures; the model cannot add a field. Untrusted free text
// (intent, declared scope, paths, extensions, file names, and file contents)
// is deliberately absent: Rego sees only enums, booleans, counts, and bounded
// numeric criteria.
func Doc(req *protocol.Request, check *capability.Check, p *plan.Plan, grant *plan.Grant) map[string]any {
	dimension := catalog.ScopeDimensionFor(req.ActionName())
	var targetInScope any = true
	if dimension != "none" {
		targetInScope = check != nil && check.Allowed
	}
	capabilityDoc := map[string]any{"allowed": false, "matched": nil, "target_in_scope": targetInScope}
	if check != nil {
		capabilityDoc["allowed"] = check.Allowed
		if check.MatchedCapability != "" {
			capabilityDoc["matched"] = check.MatchedCapability
		}
	}
	var planDoc map[string]any
	if p != nil {
		planDoc = p.PolicyDoc()
	} else {
		planDoc = map[string]any{}
	}
	var approvalDoc map[string]any
	if grant != nil {
		approvalDoc = grant.PolicyDoc()
	} else {
		approvalDoc = map[string]any{}
	}
	descriptor, ok := catalog.Lookup(req.ActionName())
	approvalClass := "none"
	if ok {
		approvalClass = string(descriptor.Approval)
	}
	return map[string]any{
		"action": req.ActionName(), "params": structuredParams(req),
		"risk":           string(catalog.RiskFor(req.ActionName())),
		"effect":         string(catalog.EffectFor(req.ActionName())),
		"read_only":      catalog.IsReadOnly(req.ActionName()),
		"path_action":    catalog.PathParam(req.ActionName()),
		"approval_class": approvalClass,
		"agent_id":       req.AgentID, "session_id": req.SessionID,
		"origin": string(req.Origin), "trust_domain": string(req.Trust),
		"capability": capabilityDoc,
		"plan":       planDoc, "approval": approvalDoc,
		"operator_confirmed": req.OperatorConfirmed,
	}
}

// structuredParams converts the validated typed params into the only shapes
// policy is allowed to reason about. No string from the proposal is passed
// through: presence is reduced to booleans and unbounded text to counts.
func structuredParams(req *protocol.Request) map[string]any {
	out := map[string]any{
		"has_target":      req.Target() != "",
		"plan_id_present": false,
	}
	switch p := req.Typed.(type) {
	case *protocol.FilesystemFindParams:
		out["min_age_days"] = p.MinAgeDays
		out["min_size_bytes"] = p.MinSizeBytes
		out["max_results"] = p.MaxResults
		out["extension_count"] = len(p.Extensions)
	case *protocol.FilesystemCleanupScanParams:
		out["min_age_days"] = p.MinAgeDays
		out["min_size_bytes"] = p.MinSizeBytes
		out["max_results"] = p.MaxCandidates
		out["extension_count"] = 0
	case *protocol.FilesystemTrashParams:
		out["plan_id_present"] = p.PlanID != ""
	case *protocol.FilesystemQuarantineParams:
		out["plan_id_present"] = p.PlanID != ""
	case *protocol.FilesystemRestoreParams:
		out["plan_id_present"] = p.PlanID != ""
	case *protocol.ProcessSignalParams:
		out["plan_id_present"] = p.PlanID != ""
	case *protocol.NetworkPreferParams:
		out["plan_id_present"] = p.PlanID != ""
	}
	return out
}

// Rego is the OPA-backed engine.
type Rego struct {
	PolicyDir string
	Binary    string
	Timeout   time.Duration
}

// NewRego resolves the binary and policy directory. An operator-supplied
// directory is kept even when invalid so evaluation fails closed; only the
// historical relative default is resolved against the installed locations.
func NewRego(policyDir, binary string, timeout time.Duration) *Rego {
	if policyDir == "" {
		policyDir = config.DefaultPolicyDir()
	} else if _, err := os.Stat(filepath.Join(policyDir, "authz.rego")); err != nil {
		if policyDir == filepath.Join("aios", "policies") {
			policyDir = config.DefaultPolicyDir()
		}
	}
	if binary == "" {
		binary = "opa"
	}
	if !filepath.IsAbs(binary) {
		if found, err := exec.LookPath(binary); err == nil {
			binary = found
		} else {
			binary = ""
		}
	}
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	return &Rego{PolicyDir: policyDir, Binary: binary, Timeout: timeout}
}

// Healthy probes the policy binary and directory with a trivial evaluation.
// It is used by /health so an operator can see that policy is actually
// available; callers must still treat a failed evaluation as DENY.
func (r *Rego) Healthy() error {
	if r == nil || r.Binary == "" {
		return errors.New("OPA binary not found")
	}
	ctx, cancel := context.WithTimeout(context.Background(), r.Timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, r.Binary, "eval", "--format=json",
		"--data", r.PolicyDir, "true")
	if err := cmd.Run(); err != nil {
		return err
	}
	return nil
}

// Evaluate runs one policy query.
func (r *Rego) Evaluate(req *protocol.Request, check *capability.Check, p *plan.Plan, grant *plan.Grant) Result {
	started := time.Now()
	document := Doc(req, check, p, grant)
	risk := string(catalog.RiskFor(req.ActionName()))
	unavailable := func(reason string) Result {
		return Result{
			Decision: Deny, Reason: reason, Risk: risk, Source: "rego:unavailable",
			InputDoc: document, LatencyMS: float64(time.Since(started)) / float64(time.Millisecond),
		}
	}
	if r.Binary == "" {
		return unavailable("OPA binary not found; policy cannot be evaluated")
	}
	body, err := json.Marshal(document)
	if err != nil {
		return unavailable("OPA input could not be encoded")
	}
	ctx, cancel := context.WithTimeout(context.Background(), r.Timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, r.Binary,
		"eval", "--format=json", "--stdin-input", "--data", r.PolicyDir,
		"data.aios.authz.decision",
	)
	cmd.Stdin = bytes.NewReader(body)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return unavailable("OPA evaluation timed out")
		}
		if exitErr, ok := err.(*exec.ExitError); ok {
			return unavailable("OPA exited " + strconv.Itoa(exitErr.ExitCode()))
		}
		return unavailable("OPA evaluation failed")
	}
	var payload struct {
		Result []struct {
			Expressions []struct {
				Value struct {
					Decision string  `json:"decision"`
					Reason   string  `json:"reason"`
					PolicyID *string `json:"policy_id"`
				} `json:"value"`
			} `json:"expressions"`
		} `json:"result"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &payload); err != nil || len(payload.Result) == 0 ||
		len(payload.Result[0].Expressions) == 0 {
		return unavailable("OPA returned an unreadable decision")
	}
	value := payload.Result[0].Expressions[0].Value
	decision := Decision(value.Decision)
	if decision != Allow && decision != Deny && decision != Confirm {
		return unavailable("OPA returned an unknown decision")
	}
	reason := value.Reason
	if len(reason) > 1000 {
		reason = reason[:1000]
	}
	return Result{
		Decision: decision, Reason: reason, Risk: risk, Source: "rego",
		PolicyID: value.PolicyID, InputDoc: document,
		LatencyMS: float64(time.Since(started)) / float64(time.Millisecond),
	}
}
