package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
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
	"aios/internal/policy"
	"aios/internal/protocol"
	"aios/internal/runtime"
)

type allowAll struct{}

func (allowAll) Evaluate(*protocol.Request, *capability.Check, *plan.Plan, *plan.Grant) policy.Result {
	return policy.Result{Decision: policy.Allow, Reason: "test", Risk: "LOW", Source: "test"}
}

func (allowAll) Healthy() error { return nil }

func testServer(t *testing.T) *Server {
	t.Helper()
	return testServerWithPolicy(t, allowAll{})
}

func testServerWithPolicy(t *testing.T, enginePolicy policy.Engine) *Server {
	t.Helper()
	gw := gateway.New("/proc", "/sys", t.TempDir())
	executor, err := actions.NewDispatcher(filepath.Join(t.TempDir(), "q"), "/proc", nil)
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
	rt.Engine = engine.New(gw, executor, rt.Capabilities, enginePolicy, audit)
	return New(rt)
}

// confirmPolicy is a small stand-in for Rego: a capability view yields
// CONFIRM, and only an explicit operator confirmation yields ALLOW.
type confirmPolicy struct{}

func (confirmPolicy) Evaluate(req *protocol.Request, check *capability.Check, _ *plan.Plan, _ *plan.Grant) policy.Result {
	if req.OperatorConfirmed {
		return policy.Result{
			Decision: policy.Allow, Reason: "operator confirmed", Risk: "MEDIUM", Source: "test",
		}
	}
	if check != nil && check.Allowed {
		return policy.Result{
			Decision: policy.Confirm, Reason: "confirmation required", Risk: "MEDIUM", Source: "test",
		}
	}
	return policy.Result{
		Decision: policy.Deny, Reason: "no capability", Risk: "MEDIUM", Source: "test",
	}
}

func call(t *testing.T, s *Server, method, target, body string) *httptest.ResponseRecorder {
	t.Helper()
	var request *http.Request
	if body == "" {
		request = httptest.NewRequest(method, target, nil)
	} else {
		request = httptest.NewRequest(method, target, strings.NewReader(body))
	}
	recorder := httptest.NewRecorder()
	s.Handler().ServeHTTP(recorder, request)
	return recorder
}

func decode(t *testing.T, recorder *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	out := map[string]any{}
	if err := json.Unmarshal(recorder.Body.Bytes(), &out); err != nil {
		t.Fatalf("invalid JSON %q: %v", recorder.Body.String(), err)
	}
	return out
}

func TestHealthReportsLoopbackSurface(t *testing.T) {
	recorder := call(t, testServer(t), http.MethodGet, "/health", "")
	if recorder.Code != http.StatusOK {
		t.Fatalf("status: %d", recorder.Code)
	}
	body := decode(t, recorder)
	if body["status"] != "ok" || body["version"] != Version {
		t.Fatalf("unexpected health: %+v", body)
	}
}

func TestSchemaListsAllowedAndForbiddenActions(t *testing.T) {
	body := decode(t, call(t, testServer(t), http.MethodGet, "/actions/schema", ""))
	allowed, _ := body["allowed_actions"].([]any)
	forbidden, _ := body["forbidden_actions"].([]any)
	if len(allowed) != 21 {
		t.Fatalf("expected 21 allowed actions, got %d", len(allowed))
	}
	found := false
	for _, name := range forbidden {
		if name == "filesystem.purge" {
			found = true
		}
	}
	if !found {
		t.Fatal("filesystem.purge missing from forbidden actions")
	}
	schemas, _ := body["params_schema"].(map[string]any)
	if _, ok := schemas["filesystem.quarantine"]; !ok {
		t.Fatal("param schema missing for filesystem.quarantine")
	}
	for _, name := range []string{"filesystem.find", "filesystem.trash"} {
		if _, ok := schemas[name]; !ok {
			t.Fatalf("param schema missing for %s", name)
		}
	}
}

func TestValidateRefusesForbiddenUnknownAndMalformed(t *testing.T) {
	server := testServer(t)
	cases := []struct {
		name string
		body string
		key  string
	}{
		{"forbidden", `{"type":"filesystem.purge","params":{"path":"/tmp/x"}}`, "forbidden_action"},
		{"unknown", `{"type":"system.reticulate","params":{}}`, "unknown_action"},
		{"malformed", `{"type":"filesystem.read","params":{}}`, "invalid_action"},
	}
	for _, tc := range cases {
		body := decode(t, call(t, server, http.MethodPost, "/actions/validate", tc.body))
		if body["valid"] != false || body["error"] != tc.key {
			t.Fatalf("%s: unexpected body %+v", tc.name, body)
		}
	}
	body := decode(t, call(t, server, http.MethodPost, "/actions/validate",
		`{"type":"system.hostname","params":{}}`))
	if body["valid"] != true {
		t.Fatalf("valid action refused: %+v", body)
	}
}

func TestExecuteDeniesWithoutCapability(t *testing.T) {
	recorder := call(t, testServer(t), http.MethodPost, "/actions/execute",
		`{"type":"system.hostname","params":{}}`)
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d: %s", recorder.Code, recorder.Body.String())
	}
	if got := recorder.Header().Get("X-AIOS-Reason"); got != "capability_missing" {
		t.Fatalf("unexpected denial reason %q", got)
	}
}

func TestExecuteAllowsWithGrant(t *testing.T) {
	server := testServer(t)
	server.rt.Capabilities.Grant("local-agent", capability.Capability{Action: "system.hostname"})
	recorder := call(t, server, http.MethodPost, "/actions/execute",
		`{"type":"system.hostname","params":{},"agent_id":"local-agent"}`)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", recorder.Code, recorder.Body.String())
	}
	body := decode(t, recorder)
	if body["decision"] != "ALLOW" || body["executed"] != true {
		t.Fatalf("unexpected verdict: %+v", body)
	}
	if body["data"] == nil {
		t.Fatal("observation data missing")
	}
}

func TestExecuteRejectsOperatorPathAbuse(t *testing.T) {
	server := testServer(t)
	for _, body := range []string{
		`{"type":"system.hostname","params":{},"origin":"kernel"}`,
		`{"type":"system.hostname","params":{},"unknown_field":1}`,
		`not json`,
	} {
		recorder := call(t, server, http.MethodPost, "/actions/execute", body)
		if recorder.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 for %q, got %d: %s", body, recorder.Code, recorder.Body.String())
		}
	}
}

func TestObservationRoutesAreOperatorDirect(t *testing.T) {
	server := testServer(t)
	for _, target := range []string{"/system/hostname", "/system/status"} {
		recorder := call(t, server, http.MethodGet, target, "")
		if recorder.Code != http.StatusOK {
			t.Fatalf("%s: expected 200, got %d: %s", target, recorder.Code, recorder.Body.String())
		}
		if body := decode(t, recorder); body["success"] != true {
			t.Fatalf("%s: unexpected body %+v", target, body)
		}
	}
	if recorder := call(t, server, http.MethodGet, "/processes/notapid", ""); recorder.Code != http.StatusBadRequest {
		t.Fatalf("invalid pid accepted: %d", recorder.Code)
	}
}

func TestFilesystemUsageReportsMountCapacity(t *testing.T) {
	recorder := call(t, testServer(t), http.MethodGet, "/filesystem/usage", "")
	if recorder.Code != http.StatusOK {
		t.Fatalf("status: %d: %s", recorder.Code, recorder.Body.String())
	}
	body := decode(t, recorder)
	data, ok := body["data"].(map[string]any)
	if !ok {
		t.Fatalf("unexpected body: %+v", body)
	}
	mounts, ok := data["mounts"].([]any)
	if !ok || len(mounts) == 0 {
		t.Fatalf("mounts missing: %+v", data)
	}
	foundRoot := false
	for _, raw := range mounts {
		mount, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		if mount["mount_point"] == "/" {
			foundRoot = true
			for _, key := range []string{"total_bytes", "used_bytes", "free_bytes", "used_percent"} {
				if mount[key] == nil {
					t.Fatalf("/ mount is missing %s: %+v", key, mount)
				}
			}
		}
	}
	if !foundRoot {
		t.Fatalf("root filesystem not reported: %+v", mounts)
	}
}

func TestHealthReportsServiceStatus(t *testing.T) {
	body := decode(t, call(t, testServer(t), http.MethodGet, "/health", ""))
	services, ok := body["services"].(map[string]any)
	if !ok {
		t.Fatalf("services missing: %+v", body)
	}
	for _, name := range []string{"api", "engine", "opa", "ledger"} {
		if _, ok := services[name]; !ok {
			t.Fatalf("service %q missing: %+v", name, services)
		}
	}
}

func TestAuditIsNewestFirstAndFiltersDenied(t *testing.T) {
	server := testServer(t)
	rows := []ledger.Entry{
		{ActionID: "act-one", Action: "system.hostname", State: "COMPLETED", Risk: "LOW", Decision: "ALLOW"},
		{ActionID: "act-two", Action: "filesystem.read", State: "DENIED", Risk: "MEDIUM", Decision: "DENY",
			DenialReason: ptr("confirmation_required")},
	}
	for _, row := range rows {
		if err := server.rt.Ledger.Record(row); err != nil {
			t.Fatal(err)
		}
	}
	body := decode(t, call(t, server, http.MethodGet, "/audit", ""))
	entries, _ := body["entries"].([]any)
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries, got %d: %+v", len(entries), body)
	}
	first, _ := entries[0].(map[string]any)
	if first["action_id"] != "act-two" {
		t.Fatalf("audit is not newest first: %+v", entries)
	}
	denied := decode(t, call(t, server, http.MethodGet, "/audit?denied=true", ""))
	deniedEntries, _ := denied["entries"].([]any)
	if len(deniedEntries) != 1 {
		t.Fatalf("denied filter returned %d rows", len(deniedEntries))
	}
}

func TestSecuritySummaryCountsAndLastEvents(t *testing.T) {
	server := testServer(t)
	for _, row := range []ledger.Entry{
		{ActionID: "act-one", State: "COMPLETED", Risk: "LOW", Decision: "ALLOW"},
		{ActionID: "act-two", State: "DENIED", Risk: "HIGH", Decision: "DENY"},
		{ActionID: "act-three", State: "VALIDATED", Risk: "MEDIUM", Decision: "CONFIRM"},
	} {
		if err := server.rt.Ledger.Record(row); err != nil {
			t.Fatal(err)
		}
	}
	body := decode(t, call(t, server, http.MethodGet, "/security/summary", ""))
	counts, _ := body["counts"].(map[string]any)
	if counts["total"] != float64(3) || counts["denied"] != float64(1) || counts["confirmed"] != float64(1) {
		t.Fatalf("unexpected counts: %+v", counts)
	}
	events, _ := body["last_events"].([]any)
	if len(events) != 3 {
		t.Fatalf("expected 3 events, got %d", len(events))
	}
}

func TestProposeReturnsConfirmWithoutExecuting(t *testing.T) {
	server := testServerWithPolicy(t, confirmPolicy{})
	path := filepath.Join(t.TempDir(), "note.txt")
	if err := os.WriteFile(path, []byte("hello"), 0o600); err != nil {
		t.Fatal(err)
	}
	recorder := call(t, server, http.MethodPost, "/actions/propose",
		`{"type":"filesystem.read","params":{"path":"`+path+`"},"intent":"look"}`)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", recorder.Code, recorder.Body.String())
	}
	body := decode(t, recorder)
	if body["decision"] != "CONFIRM" || body["requires_confirmation"] != true {
		t.Fatalf("unexpected propose body: %+v", body)
	}
	if body["denial_reason"] != nil {
		t.Fatalf("awaiting confirmation must not be a denial: %+v", body)
	}
	if body["state"] != "AWAITING_CONFIRMATION" {
		t.Fatalf("unexpected state: %v", body["state"])
	}
	if body["target"] != path {
		t.Fatalf("target missing or wrong: %+v", body["target"])
	}
	if body["data"] != nil || body["executed"] == true {
		t.Fatalf("propose executed the read: %+v", body)
	}
	states := server.rt.Ledger.States(body["action_id"].(string))
	if len(states) != 1 || states[0] != "AWAITING_CONFIRMATION" {
		t.Fatalf("unexpected audit states: %+v", states)
	}
}

func TestConfirmExecutesOneApprovedRead(t *testing.T) {
	server := testServerWithPolicy(t, confirmPolicy{})
	path := filepath.Join(t.TempDir(), "note.txt")
	if err := os.WriteFile(path, []byte("hello"), 0o600); err != nil {
		t.Fatal(err)
	}
	recorder := call(t, server, http.MethodPost, "/actions/confirm",
		`{"type":"filesystem.read","params":{"path":"`+path+`"},"origin":"ai"}`)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", recorder.Code, recorder.Body.String())
	}
	body := decode(t, recorder)
	if body["decision"] != "ALLOW" || body["executed"] != true {
		t.Fatalf("unexpected confirm body: %+v", body)
	}
	data, _ := body["data"].(map[string]any)
	if data["content"] != "hello" {
		t.Fatalf("read content missing: %+v", data)
	}
	if body["trust_domain"] != "T3" {
		t.Fatalf("operator confirmation should be user origin: %+v", body["trust_domain"])
	}
	if body["data_trust"] != "T4" {
		t.Fatalf("file content should be reported as untrusted data: %+v", body["data_trust"])
	}
}

func TestConfirmRefusesActionsOutsideTheConfirmClass(t *testing.T) {
	recorder := call(t, testServer(t), http.MethodPost, "/actions/confirm",
		`{"type":"system.hostname","params":{}}`)
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d: %s", recorder.Code, recorder.Body.String())
	}
	body := decode(t, recorder)
	if body["error"] != "not_confirmable" {
		t.Fatalf("unexpected body: %+v", body)
	}
}

func ptr(value string) *string { return &value }

func TestPlanAndApplyProcessSignal(t *testing.T) {
	child := exec.Command("sleep", "60")
	if err := child.Start(); err != nil {
		t.Fatalf("start child: %v", err)
	}
	t.Cleanup(func() {
		_ = child.Process.Kill()
		_, _ = child.Process.Wait()
	})

	server := testServer(t)
	planBody := fmt.Sprintf(
		`{"type":"process.signal","params":{"pid":%d,"signal":"TERM"},"intent":"test signal"}`,
		child.Process.Pid)
	recorder := call(t, server, http.MethodPost, "/actions/plan", planBody)
	if recorder.Code != http.StatusOK {
		t.Fatalf("plan status: %d body=%s", recorder.Code, recorder.Body.String())
	}
	planned := decode(t, recorder)
	planID, _ := planned["plan_id"].(string)
	planHash, _ := planned["plan_hash"].(string)
	steps, _ := planned["steps"].([]any)
	if planID == "" || planHash == "" || len(steps) != 1 {
		t.Fatalf("unexpected plan: %+v", planned)
	}
	step, _ := steps[0].(map[string]any)
	stepID, _ := step["step_id"].(string)

	applyBody := fmt.Sprintf(
		`{"plan_id":%q,"plan_hash":%q,"step_id":%q,"type":"process.signal"}`,
		planID, planHash, stepID)
	applied := call(t, server, http.MethodPost, "/actions/apply", applyBody)
	if applied.Code != http.StatusOK {
		t.Fatalf("apply status: %d body=%s", applied.Code, applied.Body.String())
	}
	result := decode(t, applied)
	if result["executed"] != true {
		t.Fatalf("signal was not executed: %+v", result)
	}
	data, _ := result["data"].(map[string]any)
	if data["status"] != "signal_sent" || data["signal"] != "TERM" {
		t.Fatalf("executor result was not flattened: %+v", result)
	}

	done := make(chan error, 1)
	go func() { done <- child.Wait() }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("child did not exit after TERM")
	}

	replay := call(t, server, http.MethodPost, "/actions/apply", applyBody)
	if replay.Code != http.StatusConflict {
		t.Fatalf("replayed plan was not refused: %d body=%s", replay.Code, replay.Body.String())
	}
}

func TestPlanRefusesZombie(t *testing.T) {
	child := exec.Command("true")
	if err := child.Start(); err != nil {
		t.Fatalf("start child: %v", err)
	}
	t.Cleanup(func() { _, _ = child.Process.Wait() })
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		stat, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", child.Process.Pid))
		if err == nil {
			if close := strings.LastIndexByte(string(stat), ')'); close >= 0 &&
				strings.HasPrefix(strings.TrimSpace(string(stat[close+1:])), "Z") {
				break
			}
		}
		time.Sleep(20 * time.Millisecond)
	}

	planBody := fmt.Sprintf(
		`{"type":"process.signal","params":{"pid":%d,"signal":"KILL"}}`, child.Process.Pid)
	recorder := call(t, testServer(t), http.MethodPost, "/actions/plan", planBody)
	if recorder.Code != http.StatusConflict {
		t.Fatalf("zombie plan status: %d body=%s", recorder.Code, recorder.Body.String())
	}
	body := decode(t, recorder)
	if body["error"] != "zombie_not_killable" {
		t.Fatalf("unexpected zombie refusal: %+v", body)
	}
}
