package protocol

import (
	"strings"
	"testing"
)

func TestRequestDefaultsAndTrust(t *testing.T) {
	req, err := NewRequest("process.list", nil)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if req.Trust != TrustT3 {
		t.Fatalf("ai origin must be T3, got %s", req.Trust)
	}
	params := req.Typed.(*ProcessListParams)
	if params.Limit != 50 || params.SortBy != "cpu" {
		t.Fatalf("defaults not applied: %+v", params)
	}
}

// ASI01-003: the lifecycle includes an explicit human-approval state and
// denial remains reachable from every pre-execution state.
func TestLifecycleIncludesAwaitingConfirmation(t *testing.T) {
	legal := [][2]State{
		{StateProposed, StateValidated},
		{StateValidated, StateAwaitingConfirmation},
		{StateValidated, StateAuthorized},
		{StateAwaitingConfirmation, StateAuthorized},
		{StateAuthorized, StateExecuted},
	}
	for _, edge := range legal {
		if err := AssertTransition(edge[0], edge[1]); err != nil {
			t.Errorf("rejected legal transition %v: %v", edge, err)
		}
	}
	for _, from := range []State{StateProposed, StateValidated, StateAwaitingConfirmation, StateAuthorized} {
		if !CanTransition(from, StateDenied) {
			t.Errorf("DENIED is not reachable from %s", from)
		}
	}
}

func TestTrustedOriginIsDerivedNotAccepted(t *testing.T) {
	// The protocol accepts the origin; the engine is what refuses a trusted
	// claim. Here we only assert the derivation cannot be forged.
	req, err := NewRequest("system.cpu", nil, WithOrigin(OriginKernel))
	if err != nil {
		t.Fatal(err)
	}
	if req.Trust != TrustT0 {
		t.Fatalf("kernel origin must map to T0, got %s", req.Trust)
	}
	if _, err := TrustFor("root"); err == nil {
		t.Fatal("unknown origin accepted")
	}
}

func TestForbiddenAndUnknownActionsAreRejected(t *testing.T) {
	for _, name := range []string{"filesystem.purge", "process.terminate", "shell.exec"} {
		if _, err := NewRequest(name, nil); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
	if _, err := NewRequest("not.real", nil); err == nil {
		t.Error("unknown action was accepted")
	}
}

func TestUnknownParamIsRejected(t *testing.T) {
	_, err := NewRequest("process.list", map[string]any{"limit": 5, "command": "rm -rf /"})
	if err == nil || !strings.Contains(err.Error(), "unknown param") {
		t.Fatalf("expected unknown param error, got %v", err)
	}
}

func TestParamRangesAreEnforced(t *testing.T) {
	cases := []struct {
		action string
		params map[string]any
	}{
		{"process.list", map[string]any{"limit": 0}},
		{"process.list", map[string]any{"limit": 1001}},
		{"process.list", map[string]any{"sort_by": "bogus"}},
		{"process.inspect", map[string]any{"pid": 0}},
		{"network.connections", map[string]any{"states": []any{"NOT_A_STATE"}}},
		{"filesystem.read", map[string]any{"path": "/tmp/x", "max_bytes": 0}},
		{"filesystem.cleanup_scan", map[string]any{"path": "/tmp", "min_age_days": -1}},
		{"filesystem.cleanup_scan", map[string]any{"path": "/tmp", "max_candidates": 0}},
		{"filesystem.quarantine", map[string]any{
			"path": "/tmp/x", "plan_id": "plan-1", "candidate_id": "c-1",
		}},
	}
	for _, tc := range cases {
		if _, err := NewRequest(tc.action, tc.params); err == nil {
			t.Errorf("%s accepted invalid params %v", tc.action, tc.params)
		}
	}
}

func TestPlanTargetsRequireWellFormedIDs(t *testing.T) {
	ok := map[string]any{
		"path": "/tmp/x", "plan_id": "plan-64b807b482d64989ba8e3528",
		"candidate_id": "c-211e978978e281ac",
	}
	if _, err := NewRequest("filesystem.quarantine", ok); err != nil {
		t.Fatalf("valid plan target rejected: %v", err)
	}
	for _, bad := range []map[string]any{
		{"path": "/tmp/x", "plan_id": "plan", "candidate_id": "c-211e978978e281ac"},
		{"path": "/tmp/x", "plan_id": "plan-goodid123", "candidate_id": "x-12345678"},
		{"path": "", "plan_id": "plan-goodid123", "candidate_id": "c-12345678"},
	} {
		if _, err := NewRequest("filesystem.restore", bad); err == nil {
			t.Errorf("invalid plan target accepted: %v", bad)
		}
	}
}

func TestRequestedScopeMustMatchTheTarget(t *testing.T) {
	_, err := NewRequest(
		"filesystem.stat", map[string]any{"path": "/tmp/a"},
		WithScope(map[string]any{"path": "/tmp/b"}),
	)
	if err == nil {
		t.Fatal("mismatched requested_scope accepted")
	}
	req, err := NewRequest(
		"filesystem.stat", map[string]any{"path": "/tmp/a"},
		WithScope(map[string]any{"path": "/tmp/./a"}),
	)
	if err != nil {
		t.Fatalf("normalised scope rejected: %v", err)
	}
	if req.Target() != "/tmp/a" {
		t.Fatalf("unexpected target %q", req.Target())
	}
	if _, err := NewRequest("system.cpu", nil, WithScope(map[string]any{"path": "/tmp"})); err == nil {
		t.Fatal("scope on unscoped action accepted")
	}
}

func TestNulPathIsRejected(t *testing.T) {
	if _, err := NewRequest("filesystem.read", map[string]any{"path": "/tmp/a\x00b"}); err == nil {
		t.Fatal("NUL path accepted")
	}
}

func TestUnknownEnvelopeFieldIsRejected(t *testing.T) {
	_, err := ParseRequest([]byte(`{"type":"system.cpu","command":"id"}`))
	if err == nil {
		t.Fatal("unknown envelope field accepted")
	}
}

func TestDuplicateStatesAreCollapsed(t *testing.T) {
	req, err := NewRequest("network.connections", map[string]any{
		"states": []any{"LISTEN", "LISTEN", "CLOSE"},
	})
	if err != nil {
		t.Fatal(err)
	}
	got := req.Typed.(*NetworkConnectionsParams).States
	if len(got) != 2 || got[0] != "LISTEN" || got[1] != "CLOSE" {
		t.Fatalf("unexpected states: %v", got)
	}
}

func TestLifecycleTransitions(t *testing.T) {
	if err := AssertTransition(StateExecuted, StateCompleted); err != nil {
		t.Fatal(err)
	}
	if err := AssertTransition(StateExecuted, StateProposed); err == nil {
		t.Fatal("illegal transition accepted")
	}
}
