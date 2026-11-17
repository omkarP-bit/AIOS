package main

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

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

func cliRuntime(t *testing.T, quarantine string) *runtime.Runtime {
	t.Helper()
	gw := gateway.New("/proc", "/sys", quarantine)
	executor, err := actions.NewQuarantineExecutor(quarantine)
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
	return rt
}

func capture(t *testing.T, fn func() int) (int, string) {
	t.Helper()
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	oldOut, oldErr := os.Stdout, os.Stderr
	os.Stdout, os.Stderr = writer, writer
	code := fn()
	os.Stdout, os.Stderr = oldOut, oldErr
	_ = writer.Close()
	raw, _ := io.ReadAll(reader)
	return code, string(raw)
}

func TestCleanupRoundTripThroughCLI(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "root")
	victim := filepath.Join(root, "cache", "old.txt")
	if err := os.MkdirAll(filepath.Dir(victim), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(victim, []byte("payload"), 0o640); err != nil {
		t.Fatal(err)
	}
	old := time.Now().AddDate(0, 0, -40)
	if err := os.Chtimes(victim, old, old); err != nil {
		t.Fatal(err)
	}
	rt := cliRuntime(t, filepath.Join(base, "quarantine"))
	planPath := filepath.Join(base, "plan.json")

	code, output := capture(t, func() int {
		return cleanupScan(rt, []string{root, "--plan-out", planPath, "--json"})
	})
	if code != 0 || !strings.Contains(output, "plan_hash") {
		t.Fatalf("scan failed (%d): %s", code, output)
	}
	p, err := loadPlan(planPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Steps) != 1 || p.Steps[0].Path != victim {
		t.Fatalf("unexpected plan: %+v", p)
	}

	if code, _ := capture(t, func() int {
		return cleanupQuarantine(rt, []string{planPath, "--confirm-plan-hash", "sha256:wrong"})
	}); code == 0 {
		t.Fatal("mismatched plan hash was accepted")
	}
	if _, err := os.Stat(victim); err != nil {
		t.Fatal("file moved despite a mismatched hash")
	}

	if code, output := capture(t, func() int {
		return cleanupQuarantine(rt, []string{planPath, "--confirm-plan-hash", p.PlanHash})
	}); code != 0 {
		t.Fatalf("quarantine failed: %s", output)
	}
	if _, err := os.Stat(victim); !os.IsNotExist(err) {
		t.Fatal("file still present after quarantine")
	}

	if code, output := capture(t, func() int {
		return cleanupRestore(rt, []string{planPath, "--confirm-plan-hash", p.PlanHash})
	}); code != 0 {
		t.Fatalf("restore failed: %s", output)
	}
	content, err := os.ReadFile(victim)
	if err != nil || string(content) != "payload" {
		t.Fatalf("restore lost content: %v %q", err, content)
	}
}

func TestReorderArgsAcceptsFlagsAfterPositionals(t *testing.T) {
	fs := newFlags("test")
	asJSON := fs.Bool("json", false, "")
	planOut := fs.String("plan-out", "", "")
	args := reorderArgs(fs, []string{"/tmp/root", "--json", "--plan-out", "/tmp/plan.json"})
	if err := parse(fs, args); err != nil {
		t.Fatal("parse failed:", err)
	}
	if !*asJSON || *planOut != "/tmp/plan.json" || fs.NArg() != 1 || fs.Arg(0) != "/tmp/root" {
		t.Fatalf("unexpected parse: json=%v plan=%q args=%v", *asJSON, *planOut, fs.Args())
	}
}

func TestCLIActionIDsAreAccepted(t *testing.T) {
	tests := []struct {
		action string
		id     string
		params map[string]any
	}{
		{"system.status", idStatus, nil},
		{"system.cpu", idCPU, nil},
		{"system.memory", idMemory, nil},
		{"system.hostname", idHostname, nil},
		{"process.list", idProcess, nil},
		{"process.inspect", idInspect, map[string]any{"pid": 1}},
		{"network.connections", idNetwork, nil},
		{"filesystem.list", idMounts, nil},
		{"filesystem.list", idLS, map[string]any{"path": "/"}},
	}
	for _, test := range tests {
		if _, err := protocol.NewRequest(test.action, test.params, protocol.WithActionID(test.id)); err != nil {
			t.Errorf("%s rejected id %q: %v", test.action, test.id, err)
		}
	}
}

func TestObserveCommandsRun(t *testing.T) {
	rt := cliRuntime(t, filepath.Join(t.TempDir(), "quarantine"))
	if code, output := capture(t, func() int {
		return cpuCommand(rt, []string{"--interval", "0", "--json"})
	}); code != 0 {
		t.Fatalf("cpu failed (%d): %s", code, output)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "one.txt"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, output := capture(t, func() int {
		return lsCommand(rt, []string{dir, "--json"})
	}); code != 0 {
		t.Fatalf("ls failed (%d): %s", code, output)
	}
}

func TestHelpAndSuggestions(t *testing.T) {
	code, output := capture(t, func() int { return run([]string{"help", "cpu"}) })
	if code != 0 || !strings.Contains(output, "aios cpu") || !strings.Contains(output, "Examples") {
		t.Fatalf("help failed (%d): %s", code, output)
	}
	code, output = capture(t, func() int { return run(nil) })
	if code != 0 || !strings.Contains(output, "Observe (read-only)") {
		t.Fatalf("bare help failed (%d): %s", code, output)
	}
	code, output = capture(t, func() int { return run([]string{"stauts"}) })
	if code != 2 || !strings.Contains(output, "status") {
		t.Fatalf("suggestion failed (%d): %s", code, output)
	}
}
