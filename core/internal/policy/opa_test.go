package policy

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"aios/internal/protocol"
)

func TestMissingOPAFailsClosed(t *testing.T) {
	rego := NewRego("", filepath.Join(t.TempDir(), "absent-opa"), time.Second)
	req, err := protocol.NewRequest("process.list", nil)
	if err != nil {
		t.Fatal(err)
	}
	result := rego.Evaluate(req, nil, nil, nil)
	if result.Decision != Deny || !result.Unavailable() {
		t.Fatalf("expected fail-closed denial: %+v", result)
	}
}

func TestOPADecisionIsParsed(t *testing.T) {
	script := filepath.Join(t.TempDir(), "fake-opa")
	body := `#!/bin/sh
printf '%s' '{"result":[{"expressions":[{"value":{"decision":"ALLOW","reason":"fixture","policy_id":"test"}}]}]}'
`
	if err := os.WriteFile(script, []byte(body), 0o700); err != nil {
		t.Fatal(err)
	}
	rego := NewRego("", script, time.Second)
	req, err := protocol.NewRequest("process.list", nil)
	if err != nil {
		t.Fatal(err)
	}
	result := rego.Evaluate(req, nil, nil, nil)
	if result.Decision != Allow || result.Source != "rego" || result.Reason != "fixture" {
		t.Fatalf("unexpected decision: %+v", result)
	}
}

func TestUnknownDecisionFailsClosed(t *testing.T) {
	script := filepath.Join(t.TempDir(), "fake-opa")
	body := `#!/bin/sh
printf '%s' '{"result":[{"expressions":[{"value":{"decision":"MAYBE","reason":"x"}}]}]}'
`
	if err := os.WriteFile(script, []byte(body), 0o700); err != nil {
		t.Fatal(err)
	}
	result := NewRego("", script, time.Second).Evaluate(mustRequest(t), nil, nil, nil)
	if result.Decision != Deny || !result.Unavailable() {
		t.Fatalf("unknown decision accepted: %+v", result)
	}
}

func TestNewRegoResolvesTheLegacyRelativeDefault(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	want := filepath.Join(home, ".aios", "policies")
	if err := os.MkdirAll(want, 0o755); err != nil {
		t.Fatal(err)
	}
	for name, content := range map[string]string{
		"authz.rego": "package aios.authz\n",
		"data.json":  "{}\n",
	} {
		if err := os.WriteFile(filepath.Join(want, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	rego := NewRego(filepath.Join("aios", "policies"), filepath.Join(t.TempDir(), "opa"), time.Second)
	if rego.PolicyDir != want {
		t.Fatalf("PolicyDir = %q, want %q", rego.PolicyDir, want)
	}
}

func TestNewRegoKeepsAnExplicitInvalidPolicyDir(t *testing.T) {
	invalid := filepath.Join(t.TempDir(), "missing-policies")
	rego := NewRego(invalid, filepath.Join(t.TempDir(), "opa"), time.Second)
	if rego.PolicyDir != invalid {
		t.Fatalf("PolicyDir = %q, want explicit %q", rego.PolicyDir, invalid)
	}
}

func mustRequest(t *testing.T) *protocol.Request {
	t.Helper()
	req, err := protocol.NewRequest("process.list", nil)
	if err != nil {
		t.Fatal(err)
	}
	return req
}
