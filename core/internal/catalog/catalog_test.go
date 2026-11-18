package catalog

import (
	"encoding/json"
	"os"
	"sort"
	"testing"
)

type dataAction struct {
	Risk     string   `json:"risk"`
	ReadOnly bool     `json:"read_only"`
	Path     bool     `json:"path_action"`
	Effect   string   `json:"effect"`
	Approval string   `json:"approval"`
	OWASP    []string `json:"owasp"`
}

type dataDoc struct {
	AIOS struct {
		CatalogVersion string                `json:"catalog_version"`
		Actions        map[string]dataAction `json:"allowed_actions"`
		Forbidden      []string              `json:"forbidden_actions"`
	} `json:"aios"`
}

// TestPolicyDataMatchesCatalog keeps the Rego data document and the Go
// catalog from drifting. The document is what OPA enforces; this catalog is
// what the core dispatches, and the two disagreeing is a security bug.
func TestPolicyDataMatchesCatalog(t *testing.T) {
	raw, err := os.ReadFile("../../../aios/policies/data.json")
	if err != nil {
		t.Fatalf("read policy data: %v", err)
	}
	var doc dataDoc
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("parse policy data: %v", err)
	}

	if doc.AIOS.CatalogVersion != CatalogVersion {
		t.Errorf("catalog version drift: data=%q go=%q", doc.AIOS.CatalogVersion, CatalogVersion)
	}
	if len(doc.AIOS.Actions) != len(Catalog) {
		t.Errorf("action count drift: data=%d go=%d", len(doc.AIOS.Actions), len(Catalog))
	}

	for name, d := range Catalog {
		got, ok := doc.AIOS.Actions[name]
		if !ok {
			t.Errorf("%s missing from policy data", name)
			continue
		}
		if got.Risk != string(d.Risk) {
			t.Errorf("%s risk: data=%q go=%q", name, got.Risk, d.Risk)
		}
		if got.Effect != string(d.Effect) {
			t.Errorf("%s effect: data=%q go=%q", name, got.Effect, d.Effect)
		}
		if got.Approval != string(d.Approval) {
			t.Errorf("%s approval: data=%q go=%q", name, got.Approval, d.Approval)
		}
		if got.ReadOnly != d.ReadOnly {
			t.Errorf("%s read_only: data=%v go=%v", name, got.ReadOnly, d.ReadOnly)
		}
		if got.Path != d.PathAction {
			t.Errorf("%s path_action: data=%v go=%v", name, got.Path, d.PathAction)
		}
		if !sameSet(got.OWASP, d.OWASP) {
			t.Errorf("%s owasp: data=%v go=%v", name, got.OWASP, d.OWASP)
		}
	}

	for _, name := range doc.AIOS.Forbidden {
		if !Forbidden[name] {
			t.Errorf("%s forbidden in policy but not in catalog", name)
		}
	}
	if len(doc.AIOS.Forbidden) != len(Forbidden) {
		t.Errorf("forbidden count drift: data=%d go=%d", len(doc.AIOS.Forbidden), len(Forbidden))
	}
}

// ASI05-001: permanent delete is never a legal action, and unknown actions
// stay CRITICAL rather than inheriting a low-risk default.
func TestForbiddenAndUnknownActions(t *testing.T) {
	for _, name := range []string{"filesystem.delete", "filesystem.rm", "filesystem.purge", "shell.exec"} {
		if !Forbidden[name] {
			t.Errorf("%s must stay forbidden", name)
		}
		if _, ok := Catalog[name]; ok {
			t.Errorf("%s must not be in the catalogue", name)
		}
		if EffectFor(name) != EffectForbidden {
			t.Errorf("%s must resolve to FORBIDDEN", name)
		}
		if RiskFor(name) != RiskCritical {
			t.Errorf("%s must resolve to CRITICAL", name)
		}
	}
	if RiskFor("filesystem.unknown") != RiskCritical {
		t.Fatal("unknown action must be CRITICAL")
	}
}

// ASI02-001: legacy names resolve to their current operation for grants.
func TestActionAliases(t *testing.T) {
	if Canonical("filesystem.cleanup_scan") != "filesystem.find" {
		t.Fatal("cleanup_scan alias is wrong")
	}
	if Canonical("filesystem.quarantine") != "filesystem.trash" {
		t.Fatal("quarantine alias is wrong")
	}
	if !SameAction("filesystem.quarantine", "filesystem.trash") {
		t.Fatal("aliases must compare equal")
	}
	if Canonical("filesystem.restore") != "filesystem.restore" {
		t.Fatal("unknown actions must not be rewritten")
	}
	if DescriptorFor("filesystem.find").Risk != RiskLow {
		t.Fatal("filesystem.find must be LOW")
	}
	if DescriptorFor("filesystem.trash").Risk != RiskMedium {
		t.Fatal("filesystem.trash must be MEDIUM")
	}
}

func sameSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	x := append([]string(nil), a...)
	y := append([]string(nil), b...)
	sort.Strings(x)
	sort.Strings(y)
	for i := range x {
		if x[i] != y[i] {
			return false
		}
	}
	return true
}

func TestCatalogSafety(t *testing.T) {
	for name, d := range Catalog {
		if name != d.ID {
			t.Errorf("catalog key/id mismatch: %s != %s", name, d.ID)
		}
		if Forbidden[name] {
			t.Errorf("%s is both catalogued and forbidden", name)
		}
		if d.Effect == EffectForbidden {
			t.Errorf("%s claims FORBIDDEN", name)
		}
		if d.Effect == EffectStage || d.Effect == EffectReversible {
			if d.Inverse == "" {
				t.Errorf("%s must declare an inverse", name)
			} else if _, ok := Catalog[d.Inverse]; !ok {
				t.Errorf("%s inverse %q is not catalogued", name, d.Inverse)
			}
		}
		if len(d.OWASP) == 0 {
			t.Errorf("%s has no OWASP tags", name)
		}
	}
	wantPlan := map[string]bool{
		"filesystem.trash": true, "filesystem.quarantine": true,
		"filesystem.restore": true, "process.signal": true,
		"network.prefer": true,
	}
	if len(PlanActions) != len(wantPlan) {
		t.Errorf("unexpected plan action set: %v", PlanActions)
	}
	for name := range wantPlan {
		if !PlanActions[name] {
			t.Errorf("%s is missing from the plan action set", name)
		}
	}
	for name := range ExecutorActions {
		if !PlanActions[name] {
			t.Errorf("%s is an executor action but not a plan action", name)
		}
	}
}
