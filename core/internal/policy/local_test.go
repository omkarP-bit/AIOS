package policy

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"aios/internal/filesafety"
	"aios/internal/plan"
	"aios/internal/protocol"
)

func localFixture(t *testing.T) *Local {
	t.Helper()
	rules, err := filesafety.NewRules(t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	return &Local{Rules: rules}
}

func requestWithPath(t *testing.T, action, path string) *protocol.Request {
	t.Helper()
	req, err := protocol.NewRequest(action, map[string]any{"path": path})
	if err != nil {
		t.Fatal(err)
	}
	return req
}

// ASI02-017: the local floor vetoes protected paths before OPA is consulted.
func TestLocalFloorDeniesProtectedPaths(t *testing.T) {
	local := localFixture(t)
	for _, path := range []string{"/etc/passwd", "/proc/self/environ", "/root/.bashrc"} {
		result := local.Evaluate(requestWithPath(t, "filesystem.list", path), nil, nil, nil)
		if result.Decision != Deny || result.Source != "local-floor" {
			t.Errorf("%s was not denied by the floor: %+v", path, result)
		}
	}
	req, err := protocol.NewRequest("filesystem.find", map[string]any{"root": "/etc", "max_results": 5})
	if err != nil {
		t.Fatal(err)
	}
	if result := local.Evaluate(req, nil, nil, nil); result.Decision != Deny {
		t.Fatalf("protected scan root was allowed: %+v", result)
	}
	ok, err := protocol.NewRequest("filesystem.list", map[string]any{"path": "/tmp/work/a.log"})
	if err != nil {
		t.Fatal(err)
	}
	if result := local.Evaluate(ok, nil, nil, nil); result.Decision != Allow {
		t.Fatalf("ordinary path was denied: %+v", result)
	}
}

// ASI02-018: a plan that targets a protected file is denied even though the
// trash request itself only carries a plan id.
func TestLocalFloorDeniesProtectedPlanTargets(t *testing.T) {
	local := localFixture(t)
	p := plan.Plan{
		PlanID: "plan-0123456789abcdef", Roots: []string{"/tmp/work"},
		Steps: []plan.Step{{StepID: "step-1", Action: "filesystem.trash", Path: "/etc/passwd"}},
	}
	req, err := protocol.NewRequest("filesystem.trash", map[string]any{"plan_id": p.PlanID})
	if err != nil {
		t.Fatal(err)
	}
	if result := local.Evaluate(req, nil, &p, nil); result.Decision != Deny {
		t.Fatalf("protected plan target was allowed: %+v", result)
	}
}

func fakeOPA(t *testing.T, decision, reason string) *Rego {
	t.Helper()
	script := filepath.Join(t.TempDir(), "fake-opa")
	body := "#!/bin/sh\nprintf '%s' '{\"result\":[{\"expressions\":[{\"value\":{\"decision\":\"" + decision + "\",\"reason\":\"" + reason + "\"}}]}]}'\n"
	if err := os.WriteFile(script, []byte(body), 0o700); err != nil {
		t.Fatal(err)
	}
	return NewRego("", script, time.Second)
}

// ASI02-019: OPA ALLOW cannot override a local floor DENY, but OPA DENY can
// narrow a local ALLOW.
func TestStricterTakesTheStricterDecision(t *testing.T) {
	local := localFixture(t)
	allowedOPA := fakeOPA(t, "ALLOW", "opa allowed")
	combined := NewStricter(local, allowedOPA)

	if result := combined.Evaluate(requestWithPath(t, "filesystem.list", "/etc/passwd"), nil, nil, nil); result.Decision != Deny {
		t.Fatalf("OPA ALLOW overrode the floor: %+v", result)
	}
	ok := requestWithPath(t, "filesystem.list", "/tmp/work/a.log")
	if result := combined.Evaluate(ok, nil, nil, nil); result.Decision != Allow {
		t.Fatalf("combined engine denied a safe path: %+v", result)
	}

	combined.OPA = fakeOPA(t, "DENY", "opa denied")
	if result := combined.Evaluate(ok, nil, nil, nil); result.Decision != Deny || result.Reason != "opa denied" {
		t.Fatalf("OPA DENY did not win: %+v", result)
	}
}

func TestStricterDeniesWhenOPAIsUnavailable(t *testing.T) {
	local := localFixture(t)
	combined := NewStricter(local, NewRego("", filepath.Join(t.TempDir(), "absent"), time.Second))
	result := combined.Evaluate(requestWithPath(t, "filesystem.list", "/tmp/a.log"), nil, nil, nil)
	if result.Decision != Deny || !result.Unavailable() {
		t.Fatalf("unavailable OPA was not fail-closed: %+v", result)
	}
}
