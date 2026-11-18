package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"aios/internal/actions"
	"aios/internal/capability"
	"aios/internal/config"
	"aios/internal/engine"
	"aios/internal/gateway"
	"aios/internal/ledger"
	"aios/internal/plan"
	"aios/internal/runtime"
)

// testCleanupServer wires a fully configured cleanup surface. The policy is
// allow-all so these tests exercise the plumbing, not policy decisions (which
// are covered by the Rego suite and the engine tests).
func testCleanupServer(t *testing.T) (*Server, *runtime.Runtime) {
	t.Helper()
	quarantine := filepath.Join(t.TempDir(), "q")
	gw := gateway.New("/proc", "/sys", quarantine)
	executor, err := actions.NewDispatcher(quarantine, "/proc", nil)
	if err != nil {
		t.Fatal(err)
	}
	audit, err := ledger.New("")
	if err != nil {
		t.Fatal(err)
	}
	rt := &runtime.Runtime{
		Settings: config.Settings{ProcRoot: "/proc", SysRoot: "/sys"},
		Gateway:  gw, Executor: executor, Ledger: audit,
		Capabilities: capability.EmptyManager(),
		Plans:        plan.NewRegistry(time.Minute),
	}
	rt.Engine = engine.New(gw, executor, rt.Capabilities, allowAll{}, audit)
	authority, err := plan.NewAuthority([]byte("0123456789abcdef0123456789abcdef"), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	rt.ApprovalAuthority = authority
	rt.Cleanups = plan.NewCleanupRegistry(time.Minute)
	rt.Cleanup = engine.NewCleanupService(rt.Engine, rt.Cleanups, authority)
	return New(rt), rt
}

func oldCleanupFile(t *testing.T, root, name string) string {
	t.Helper()
	path := filepath.Join(root, name)
	if err := os.WriteFile(path, []byte("old payload"), 0o600); err != nil {
		t.Fatal(err)
	}
	old := time.Now().AddDate(0, 0, -40)
	if err := os.Chtimes(path, old, old); err != nil {
		t.Fatal(err)
	}
	return path
}

func decodeBody(t *testing.T, recorder *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var body map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatalf("invalid response %q: %v", recorder.Body.String(), err)
	}
	return body
}

// ASI02-028: the full operator flow is propose -> inspect -> approve -> trash,
// with each state transition driven by a separate request. A caller never
// supplies target paths, and the origin is set by the server.
func TestCleanupProposeApproveTrashFlow(t *testing.T) {
	root := t.TempDir()
	first := oldCleanupFile(t, root, "a.log")
	second := oldCleanupFile(t, root, "b.log")
	server, rt := testCleanupServer(t)

	criteria := map[string]any{
		"root": root, "min_age_days": 30, "max_results": 100,
	}
	body, _ := json.Marshal(criteria)
	recorder := call(t, server, http.MethodPost, "/plans", string(body))
	if recorder.Code != http.StatusOK {
		t.Fatalf("propose: %d %s", recorder.Code, recorder.Body.String())
	}
	proposal := decodeBody(t, recorder)
	planID, _ := proposal["plan_id"].(string)
	planHash, _ := proposal["plan_hash"].(string)
	if planID == "" || planHash == "" {
		t.Fatalf("missing plan identity: %+v", proposal)
	}
	if proposal["status"] != string(plan.CleanupPendingApproval) {
		t.Fatalf("new plan must await approval: %+v", proposal)
	}
	planBody, _ := proposal["plan"].(map[string]any)
	entries, _ := planBody["entries"].([]any)
	if len(entries) != 2 {
		t.Fatalf("expected two captured entries: %+v", planBody)
	}

	// A wrong hash is refused; no capability is granted and no file is moved.
	wrong, _ := json.Marshal(map[string]any{"plan_hash": "sha256:wrong", "operator": "alice"})
	recorder = call(t, server, http.MethodPost, "/plans/"+planID+"/approve", string(wrong))
	if recorder.Code != http.StatusConflict {
		t.Fatalf("wrong hash accepted: %d %s", recorder.Code, recorder.Body.String())
	}

	approve, _ := json.Marshal(map[string]any{"plan_hash": planHash, "operator": "alice"})
	recorder = call(t, server, http.MethodPost, "/plans/"+planID+"/approve", string(approve))
	if recorder.Code != http.StatusOK {
		t.Fatalf("approve: %d %s", recorder.Code, recorder.Body.String())
	}
	if decodeBody(t, recorder)["status"] != string(plan.CleanupApproved) {
		t.Fatal("approved plan did not reach APPROVED")
	}

	for _, grant := range rt.Capabilities.CapabilitiesFor("local-agent") {
		if grant.Action == "filesystem.trash" && len(grant.Scope) != 2 {
			t.Fatalf("approval must grant every exact path at once: %+v", grant)
		}
	}

	recorder = call(t, server, http.MethodPost, "/plans/"+planID+"/trash", "")
	if recorder.Code != http.StatusOK {
		t.Fatalf("trash: %d %s", recorder.Code, recorder.Body.String())
	}
	trashed := decodeBody(t, recorder)
	for _, path := range []string{first, second} {
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Errorf("file was not trashed: %s (%v)", path, err)
		}
	}
	verdict, _ := trashed["verdict"].(map[string]any)
	actionID, _ := verdict["action_id"].(string)
	if actionID == "" {
		t.Fatalf("trash verdict has no action id: %+v", verdict)
	}

	// Server-set origin is recorded on every audit row.
	for _, entry := range rt.Ledger.ByAction(actionID) {
		if entry.Origin != "user" {
			t.Fatalf("origin was not set server-side: %+v", entry)
		}
	}
	if !strings.Contains(rt.Ledger.ByAction(actionID)[0].Action, "trash") {
		t.Fatal("audit action does not match the trash request")
	}

	recorder = call(t, server, http.MethodGet, "/plans/"+planID, "")
	if recorder.Code != http.StatusOK {
		t.Fatalf("get plan: %d %s", recorder.Code, recorder.Body.String())
	}
	stored := decodeBody(t, recorder)
	storedPlan, _ := stored["plan"].(map[string]any)
	if storedPlan["status"] != string(plan.CleanupExecuted) {
		t.Fatalf("executed plan status: %+v", storedPlan)
	}

	recorder = call(t, server, http.MethodGet, "/plans", "")
	if recorder.Code != http.StatusOK || len(decodeBody(t, recorder)["plans"].([]any)) != 1 {
		t.Fatalf("list plans: %d %s", recorder.Code, recorder.Body.String())
	}

	// Restore is looked up by the durable action id, never by a supplied path.
	recorder = call(t, server, http.MethodPost, "/restore/"+actionID, "")
	if recorder.Code != http.StatusOK {
		t.Fatalf("restore: %d %s", recorder.Code, recorder.Body.String())
	}
	for _, path := range []string{first, second} {
		if _, err := os.Stat(path); err != nil {
			t.Errorf("file was not restored: %s (%v)", path, err)
		}
	}
}

// ASI02-029: filesystem.find is read-only and reports only the deterministic
// scan result. It never mutates and never accepts a target list.
func TestFilesystemFindIsReadOnly(t *testing.T) {
	root := t.TempDir()
	oldCleanupFile(t, root, "a.log")
	server, _ := testCleanupServer(t)
	criteria, _ := json.Marshal(map[string]any{"root": root, "min_age_days": 30})
	recorder := call(t, server, http.MethodPost, "/filesystem/find", string(criteria))
	if recorder.Code != http.StatusOK {
		t.Fatalf("find: %d %s", recorder.Code, recorder.Body.String())
	}
	body := decodeBody(t, recorder)
	scan, _ := body["scan"].(map[string]any)
	if scan["total"] != float64(1) {
		t.Fatalf("unexpected scan result: %+v", scan)
	}
	if _, err := os.Stat(filepath.Join(root, "a.log")); err != nil {
		t.Fatalf("find mutated a file: %v", err)
	}
}

// ASI02-030: capability grants are operator-driven, action-checked, and
// revocable. Forbidden actions cannot be granted through this surface.
func TestCapabilityGrantAndRevoke(t *testing.T) {
	server, rt := testCleanupServer(t)
	grant, _ := json.Marshal(map[string]any{
		"agent_id": "agent-7", "action": "filesystem.find",
		"scope": []string{"/tmp"}, "granted_by": "operator", "ttl": "5m",
	})
	recorder := call(t, server, http.MethodPost, "/capabilities/grant", string(grant))
	if recorder.Code != http.StatusOK {
		t.Fatalf("grant: %d %s", recorder.Code, recorder.Body.String())
	}
	if len(rt.Capabilities.CapabilitiesFor("agent-7")) != 1 {
		t.Fatal("grant was not installed")
	}
	forbidden, _ := json.Marshal(map[string]any{
		"agent_id": "agent-7", "action": "filesystem.delete", "scope": []string{"/tmp"},
	})
	if recorder = call(t, server, http.MethodPost, "/capabilities/grant", string(forbidden)); recorder.Code != http.StatusForbidden {
		t.Fatalf("forbidden action was grantable: %d", recorder.Code)
	}
	revoke, _ := json.Marshal(map[string]any{"agent_id": "agent-7", "action": "filesystem.find"})
	if recorder = call(t, server, http.MethodPost, "/capabilities/revoke", string(revoke)); recorder.Code != http.StatusOK {
		t.Fatalf("revoke: %d %s", recorder.Code, recorder.Body.String())
	}
	if len(rt.Capabilities.CapabilitiesFor("agent-7")) != 0 {
		t.Fatal("revoke did not remove the grant")
	}
}
