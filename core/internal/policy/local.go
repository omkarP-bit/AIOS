package policy

import (
	"errors"
	"os"

	"aios/internal/capability"
	"aios/internal/catalog"
	"aios/internal/filesafety"
	"aios/internal/plan"
	"aios/internal/protocol"
)

// ErrOPAUnavailable is returned by health checks when no OPA engine is wired.
var ErrOPAUnavailable = errors.New("OPA policy engine is not configured")

// Local is the deterministic policy floor. It never grants anything on its
// own: an ALLOW here only means the non-negotiable local rules did not veto.
type Local struct {
	Rules     filesafety.Rules
	PolicyDir string
}

// NewLocal loads the policy-declared protected paths and unions them with the
// Go hard floor.
func NewLocal(policyDir string) (*Local, error) {
	rules, err := filesafety.Load(policyDir)
	if err != nil {
		return nil, err
	}
	return &Local{Rules: rules, PolicyDir: policyDir}, nil
}

// Evaluate applies only veto rules. It is safe to combine with any OPA result:
// a local DENY can never be overridden by Rego.
func (l *Local) Evaluate(req *protocol.Request, check *capability.Check, p *plan.Plan, grant *plan.Grant) Result {
	document := Doc(req, check, p, grant)
	risk := string(catalog.RiskFor(req.ActionName()))
	deny := func(reason string) Result {
		return Result{
			Decision: Deny, Reason: reason, Risk: risk,
			Source: "local-floor", InputDoc: document,
		}
	}
	if l == nil {
		return deny("local policy floor is not configured")
	}
	if catalog.Forbidden[req.ActionName()] {
		return deny("forbidden action")
	}

	targets := []string{}
	if catalog.PathParam(req.ActionName()) {
		if target := req.Target(); target != "" {
			targets = append(targets, target)
		}
		if p != nil {
			for _, step := range p.Steps {
				if step.Path != "" {
					targets = append(targets, step.Path)
				}
				if step.Target != "" && catalog.PathParam(step.Action) {
					targets = append(targets, step.Target)
				}
			}
		}
		if len(targets) == 0 {
			return deny("path action has no resolved target")
		}
	}
	for _, target := range targets {
		if l.Rules.IsProtected(target) {
			return deny("protected path denied by the local floor")
		}
	}

	// Mutations additionally re-check realpath identity against the approved
	// root. Restore is exempt because the source no longer exists by design;
	// its sidecar and executor re-validate the payload before moving it back.
	if !catalog.IsReadOnly(req.ActionName()) && catalog.PathParam(req.ActionName()) &&
		req.ActionName() != "filesystem.restore" && p != nil && len(p.Roots) > 0 {
		for _, target := range targets {
			if _, err := l.Rules.ValidateTarget(target, p.Roots[0], uint32(os.Getuid())); err != nil {
				return deny("target failed the local realpath floor")
			}
		}
	}
	return Result{
		Decision: Allow, Reason: "local floor passed", Risk: risk,
		Source: "local-floor", InputDoc: document,
	}
}

// Stricter combines the local veto with OPA. OPA may narrow what local allows;
// it can never widen what local denies. An unavailable OPA is always denied.
type Stricter struct {
	Local *Local
	OPA   *Rego
}

// NewStricter wires the local floor and the OPA engine together.
func NewStricter(local *Local, opa *Rego) *Stricter {
	if local == nil {
		rules, _ := filesafety.NewRules("", nil)
		local = &Local{Rules: rules}
	}
	return &Stricter{Local: local, OPA: opa}
}

// Evaluate returns the stricter of the two decisions.
func (s *Stricter) Evaluate(req *protocol.Request, check *capability.Check, p *plan.Plan, grant *plan.Grant) Result {
	if s == nil {
		return Result{Decision: Deny, Reason: "policy engine is not configured", Risk: string(catalog.RiskFor(req.ActionName())), Source: "local-floor"}
	}
	local := s.Local.Evaluate(req, check, p, grant)
	if s.OPA == nil {
		return Result{
			Decision: Deny, Reason: "OPA policy engine is not configured",
			Risk: local.Risk, Source: "rego:unavailable", InputDoc: local.InputDoc,
		}
	}
	opa := s.OPA.Evaluate(req, check, p, grant)
	if opa.Decision == Deny && opa.Unavailable() {
		return opa
	}
	if local.Decision == Deny {
		return local
	}
	if opa.Decision == Deny {
		return opa
	}
	if opa.Decision == Confirm || local.Decision == Confirm {
		return Result{
			Decision: Confirm, Reason: "human confirmation required",
			Risk: local.Risk, Source: "local-floor+rego", InputDoc: opa.InputDoc,
		}
	}
	return Result{
		Decision: Allow, Reason: "policy allowed by local floor and OPA",
		Risk: local.Risk, Source: "local-floor+rego", InputDoc: opa.InputDoc,
	}
}

// Healthy reports OPA availability. The local floor is in-process and always
// present once constructed.
func (s *Stricter) Healthy() error {
	if s == nil || s.OPA == nil {
		return ErrOPAUnavailable
	}
	return s.OPA.Healthy()
}
