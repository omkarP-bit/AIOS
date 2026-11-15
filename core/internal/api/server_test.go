package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"aios/internal/actions"
	"aios/internal/capability"
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

func testServer(t *testing.T) *Server {
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
	rt := &runtime.Runtime{
		Gateway: gw, Executor: executor, Ledger: audit,
		Capabilities: capability.EmptyManager(),
	}
	rt.Engine = engine.New(gw, executor, rt.Capabilities, allowAll{}, audit)
	return New(rt)
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
	if len(allowed) != 14 {
		t.Fatalf("expected 14 allowed actions, got %d", len(allowed))
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
