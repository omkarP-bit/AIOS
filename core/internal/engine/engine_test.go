package engine

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"aios/internal/actions"
	"aios/internal/capability"
	"aios/internal/gateway"
	"aios/internal/ledger"
	"aios/internal/plan"
	"aios/internal/policy"
	"aios/internal/protocol"
)

type fixedPolicy struct {
	decision policy.Decision
	reason   string
}

func (f fixedPolicy) Evaluate(*protocol.Request, *capability.Check, *plan.Plan, *plan.Grant) policy.Result {
	return policy.Result{
		Decision: f.decision, Reason: f.reason, Risk: "LOW", Source: "test",
	}
}

func testEngine(t *testing.T, p policy.Engine) *Engine {
	t.Helper()
	gw := gateway.New("/proc", "/sys", t.TempDir())
	executor, err := actions.NewQuarantineExecutor(filepath.Join(t.TempDir(), "q"))
	if err != nil {
		t.Fatal(err)
	}
	audit, err := ledger.New("")
	if err != nil {
		t.Fatal(err)
	}
	return New(gw, executor, capability.NewManager(), p, audit)
}

func TestReadActionCompletesWithObservation(t *testing.T) {
	e := testEngine(t, fixedPolicy{policy.Allow, "allowed"})
	req, err := protocol.NewRequest("process.list", nil)
	if err != nil {
		t.Fatal(err)
	}
	verdict := e.Process(req, nil, nil)
	if verdict.Decision != policy.Allow || !verdict.Executed {
		t.Fatalf("unexpected verdict: %+v", verdict)
	}
	if verdict.State != protocol.StateCompleted || verdict.Observation == nil {
		t.Fatalf("observation missing: %+v", verdict)
	}
	if !verdict.Observation.Trusted() {
		// The gateway envelope must be a trusted domain (T2).
		t.Fatalf("observation provenance not trusted: %s", verdict.Observation.TrustDomain)
	}
	states := e.Ledger.States(req.ActionID)
	if len(states) < 2 || states[len(states)-1] != string(protocol.StateCompleted) {
		t.Fatalf("unexpected ledger states: %v", states)
	}
}

func TestCapabilityDenialIsDenyByDefault(t *testing.T) {
	e := testEngine(t, fixedPolicy{policy.Allow, "allowed"})
	req, err := protocol.NewRequest("filesystem.read", map[string]any{"path": "/etc/hostname"})
	if err != nil {
		t.Fatal(err)
	}
	verdict := e.Process(req, nil, nil)
	if verdict.Decision != policy.Deny || verdict.State != protocol.StateDenied {
		t.Fatalf("expected denial, got %+v", verdict)
	}
	if verdict.DenialReason == nil || *verdict.DenialReason != CapabilityMissing {
		t.Fatalf("unexpected denial reason: %+v", verdict.DenialReason)
	}
}

func TestTrustedOriginClaimIsDenied(t *testing.T) {
	e := testEngine(t, fixedPolicy{policy.Allow, "allowed"})
	req, err := protocol.NewRequest("system.cpu", nil, protocol.WithOrigin(protocol.OriginKernel))
	if err != nil {
		t.Fatal(err)
	}
	verdict := e.Process(req, nil, nil)
	if verdict.Decision != policy.Deny || verdict.DenialReason == nil || *verdict.DenialReason != PolicyDeny {
		t.Fatalf("trusted claim accepted: %+v", verdict)
	}
}

func TestPolicyDenialAndUnavailableFailClosed(t *testing.T) {
	for _, tc := range []struct {
		name     string
		result   policy.Result
		expected DenialReason
	}{
		{"deny", policy.Result{Decision: policy.Deny, Reason: "no", Source: "rego"}, PolicyDeny},
		{"unavailable", policy.Result{Decision: policy.Deny, Reason: "no opa", Source: "rego:unavailable"}, PolicyUnavailable},
	} {
		e := testEngine(t, fixedPolicy{tc.result.Decision, tc.result.Reason})
		if tc.expected == PolicyUnavailable {
			e.Policy = unavailablePolicy{}
		}
		req, _ := protocol.NewRequest("process.list", nil)
		verdict := e.Process(req, nil, nil)
		if verdict.Decision != policy.Deny || verdict.DenialReason == nil || *verdict.DenialReason != tc.expected {
			t.Fatalf("%s: unexpected verdict %+v", tc.name, verdict)
		}
	}
}

type unavailablePolicy struct{}

func (unavailablePolicy) Evaluate(*protocol.Request, *capability.Check, *plan.Plan, *plan.Grant) policy.Result {
	return policy.Result{Decision: policy.Deny, Reason: "no opa", Source: "rego:unavailable"}
}

func TestMutationRequiresPlan(t *testing.T) {
	e := testEngine(t, fixedPolicy{policy.Allow, "approved"})
	manager := capability.EmptyManager()
	manager.Grant("local-agent", capability.Capability{
		Action: "filesystem.quarantine", Scope: []string{"/tmp/whatever"},
	})
	e.Capabilities = manager
	req, err := protocol.NewRequest("filesystem.quarantine", map[string]any{
		"path": "/tmp/whatever", "plan_id": "plan-0123456789abcdef01234567",
		"candidate_id": "c-0123456789abcdef",
	}, protocol.WithOrigin(protocol.OriginUser))
	if err != nil {
		t.Fatal(err)
	}
	verdict := e.Process(req, nil, nil)
	if verdict.Decision != policy.Deny || verdict.DenialReason == nil || *verdict.DenialReason != PlanRequired {
		t.Fatalf("mutation without a plan accepted: %+v", verdict)
	}
}

func TestMutationRoundTripThroughEngine(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "cache", "victim.txt")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("payload"), 0o640); err != nil {
		t.Fatal(err)
	}
	old := time.Now().AddDate(0, 0, -40)
	if err := os.Chtimes(path, old, old); err != nil {
		t.Fatal(err)
	}
	result, err := actions.ScanCandidates(root, actions.ScanOptions{MinAgeDays: 30})
	if err != nil || len(result.Candidates) != 1 {
		t.Fatalf("scan: %v %+v", err, result)
	}
	p := plan.FromCandidates(result.Candidates, root, "local-agent", "cli", nil, 500, 1<<30, time.Now())
	authority, err := plan.NewAuthority([]byte("0123456789abcdef0123456789abcdef"), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	token, err := authority.Mint(p, "uid:1000", 0)
	if err != nil {
		t.Fatal(err)
	}
	grant, err := authority.Verify(token, p, true, time.Now())
	if err != nil {
		t.Fatal(err)
	}

	e := testEngine(t, fixedPolicy{policy.Allow, "approved plan"})
	manager := capability.EmptyManager()
	manager.Grant("local-agent", capability.Capability{
		Action: "filesystem.quarantine",
		Scope:  []string{p.Steps[0].Path}, GrantedBy: "operator-cli",
	})
	manager.Grant("local-agent", capability.Capability{
		Action: "filesystem.restore",
		Scope:  []string{p.Steps[0].Path}, GrantedBy: "operator-cli",
	})
	e.Capabilities = manager

	req, _ := protocol.NewRequest("filesystem.quarantine", map[string]any{
		"path": p.Steps[0].Path, "plan_id": p.PlanID,
		"candidate_id": p.Steps[0].CandidateID,
	}, protocol.WithOrigin(protocol.OriginUser))
	verdict := e.Process(req, &p, &grant)
	if verdict.Decision != policy.Allow || !verdict.Executed {
		t.Fatalf("quarantine denied: %+v", verdict)
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatal("file still present after quarantine")
	}

	restoreReq, _ := protocol.NewRequest("filesystem.restore", map[string]any{
		"path": p.Steps[0].Path, "plan_id": p.PlanID,
		"candidate_id": p.Steps[0].CandidateID,
	}, protocol.WithOrigin(protocol.OriginUser))
	restored := e.Process(restoreReq, &p, &grant)
	if restored.Decision != policy.Allow || !restored.Executed {
		t.Fatalf("restore denied: %+v", restored)
	}
	content, err := os.ReadFile(path)
	if err != nil || string(content) != "payload" {
		t.Fatalf("restore failed: %v %q", err, content)
	}
}

// ASI01-001: CONFIRM is a real lifecycle state, not a denial. The operator
// can still refuse later, but the proposal is not marked DENIED.
func TestConfirmEntersAwaitingState(t *testing.T) {
	e := testEngine(t, fixedPolicy{policy.Confirm, "needs a human"})
	e.Capabilities.Grant("local-agent", capability.Capability{
		Action: "filesystem.read", Scope: []string{"/tmp/a.log"}, GrantedBy: "test",
	})
	req, err := protocol.NewRequest("filesystem.read", map[string]any{"path": "/tmp/a.log"})
	if err != nil {
		t.Fatal(err)
	}
	verdict := e.Authorize(req, nil, nil)
	if verdict.Decision != policy.Confirm || verdict.State != protocol.StateAwaitingConfirmation {
		t.Fatalf("confirm was not awaited: %+v", verdict)
	}
	if verdict.DenialReason != nil {
		t.Fatalf("awaiting confirmation must not be a denial: %v", *verdict.DenialReason)
	}
	states := e.Ledger.States(req.ActionID)
	last := states[len(states)-1]
	if last != string(protocol.StateAwaitingConfirmation) {
		t.Fatalf("ledger never recorded AWAITING_CONFIRMATION: %v", states)
	}
}

// ASI01-002: a model-origin proposal can never execute a mutation, even with
// a grant and an otherwise valid approval in place.
func TestMutationRequiresUserOrigin(t *testing.T) {
	e := testEngine(t, fixedPolicy{policy.Allow, "allowed"})
	req, err := protocol.NewRequest("filesystem.quarantine", map[string]any{
		"path": "/tmp/a.log", "plan_id": "plan-0123456789abcdef",
		"candidate_id": "c-0123456789abcdef",
	})
	if err != nil {
		t.Fatal(err)
	}
	verdict := e.Process(req, nil, nil)
	if verdict.Decision != policy.Deny || verdict.DenialReason == nil || *verdict.DenialReason != PolicyDeny {
		t.Fatalf("AI-origin mutation was accepted: %+v", verdict)
	}
}

// ASI03-003: an approval missing its operator identity is refused before the
// executor is called.
func TestExecutorRequiresValidApproval(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "old.log")
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	result, err := actions.ScanCandidates(root, actions.ScanOptions{MinAgeDays: 0})
	if err != nil || len(result.Candidates) != 1 {
		t.Fatalf("scan: %v %+v", err, result)
	}
	p := plan.FromCandidates(result.Candidates, root, "local-agent", "cli", nil, 500, 1<<30, time.Now())
	authority, err := plan.NewAuthority([]byte("0123456789abcdef0123456789abcdef"), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	token, err := authority.Mint(p, "operator", 0)
	if err != nil {
		t.Fatal(err)
	}
	grant, err := authority.Verify(token, p, true, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	grant.ApprovedBy = ""

	e := testEngine(t, fixedPolicy{policy.Allow, "allowed"})
	e.Capabilities.Grant("local-agent", capability.Capability{
		Action: "filesystem.quarantine", Scope: []string{path}, GrantedBy: "test",
	})
	req, _ := protocol.NewRequest("filesystem.quarantine", map[string]any{
		"path": path, "plan_id": p.PlanID, "candidate_id": p.Steps[0].CandidateID,
	}, protocol.WithOrigin(protocol.OriginUser))
	verdict := e.Process(req, &p, &grant)
	if verdict.Decision != policy.Deny || verdict.DenialReason == nil || *verdict.DenialReason != ApprovalInvalid {
		t.Fatalf("invalid approval was accepted: %+v", verdict)
	}
}

// ASI02-020: a plan-only trash request derives its capability targets from the
// engine-built plan, not from caller-supplied paths.
func TestPlanOnlyRequestChecksEveryPlanTarget(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "old.log")
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	p := plan.Build("filesystem.trash", []string{root}, []plan.Step{{
		StepID: "step-1", Action: "filesystem.trash", Path: path,
	}}, plan.Limits{MaxItems: 1, MaxBytes: 1 << 20}, "local-agent", "cli", nil, time.Now())

	e := testEngine(t, fixedPolicy{policy.Allow, "allowed"})
	e.Capabilities.Grant("local-agent", capability.Capability{
		Action: "filesystem.trash", Scope: []string{root + "/*"}, GrantedBy: "test",
	})
	req, err := protocol.NewRequest("filesystem.trash", map[string]any{"plan_id": p.PlanID},
		protocol.WithOrigin(protocol.OriginUser))
	if err != nil {
		t.Fatal(err)
	}
	verdict := e.Authorize(req, &p, nil)
	if verdict.Decision != policy.Allow || verdict.Capability == nil || !verdict.Capability.Allowed {
		t.Fatalf("plan-only target was not authorized: %+v", verdict)
	}
}

func TestCompletedLedgerRowKeepsTheExactTarget(t *testing.T) {
	e := testEngine(t, fixedPolicy{policy.Allow, "allowed"})
	e.Capabilities.Grant("local-agent", capability.Capability{
		Action: "process.inspect", Scope: []string{"1"},
		GrantedBy: "test", Reason: "target audit test",
	})
	req, err := protocol.NewRequest("process.inspect", map[string]any{"pid": 1})
	if err != nil {
		t.Fatal(err)
	}
	verdict := e.Process(req, nil, nil)
	if verdict.Decision != policy.Allow {
		t.Fatalf("unexpected verdict: %+v", verdict)
	}
	entries := e.Ledger.ByAction(req.ActionID)
	if len(entries) == 0 {
		t.Fatal("no ledger rows")
	}
	last := entries[len(entries)-1]
	if last.State != string(protocol.StateCompleted) {
		t.Fatalf("last state is %q, want COMPLETED", last.State)
	}
	if last.Target == nil || *last.Target != "1" {
		t.Fatalf("completed row lost its target: %+v", last)
	}
}
