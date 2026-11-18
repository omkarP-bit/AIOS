package actions

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"aios/internal/model"
	"aios/internal/plan"
	"aios/internal/protocol"
)

func oldFile(t *testing.T, root, name string) string {
	t.Helper()
	path := filepath.Join(root, name)
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
	return path
}

func TestScanIsDeterministicAndBounded(t *testing.T) {
	root := t.TempDir()
	oldFile(t, root, "cache/foo.txt")
	oldFile(t, root, "cache/bar.txt")
	fresh := filepath.Join(root, "fresh.txt")
	if err := os.WriteFile(fresh, []byte("new"), 0o644); err != nil {
		t.Fatal(err)
	}
	result, err := ScanCandidates(root, ScanOptions{MinAgeDays: 30})
	if err != nil {
		t.Fatal(err)
	}
	if result.Total != 2 || len(result.Candidates) != 2 {
		t.Fatalf("expected two candidates, got %+v", result)
	}
	if result.Candidates[0].Path != filepath.Join(root, "cache/bar.txt") {
		t.Fatalf("candidates not sorted: %+v", result.Candidates)
	}
	if result.Candidates[0].Tags[0] != "cache" {
		t.Fatalf("unexpected tags: %v", result.Candidates[0].Tags)
	}
	if result.GeneratedAt.IsZero() {
		t.Fatal("missing generated_at")
	}
	again, _ := ScanCandidates(root, ScanOptions{MinAgeDays: 30})
	if again.Candidates[0].CandidateID != result.Candidates[0].CandidateID {
		t.Fatal("candidate id is not deterministic")
	}

	limited, _ := ScanCandidates(root, ScanOptions{MinAgeDays: 30, MaxCandidates: 1})
	if len(limited.Candidates) != 1 || !limited.Truncated {
		t.Fatalf("limit not enforced: %+v", limited)
	}
}

func TestScanSkipsSensitiveAndHidden(t *testing.T) {
	root := t.TempDir()
	oldFile(t, root, ".hidden")
	oldFile(t, root, "run.pid")
	result, err := ScanCandidates(root, ScanOptions{MinAgeDays: 30})
	if err != nil {
		t.Fatal(err)
	}
	if result.Total != 0 {
		t.Fatalf("skipped files were scanned: %+v", result.Candidates)
	}
	if result.Skipped < 2 {
		t.Fatalf("skips not counted: %+v", result)
	}
	if _, err := ScanCandidates(filepath.Join(root, "missing"), ScanOptions{}); err == nil {
		t.Fatal("missing root accepted")
	}
}

func quarantineFixture(t *testing.T) (*QuarantineExecutor, plan.Plan, model.Candidate) {
	t.Helper()
	root := t.TempDir()
	oldFile(t, root, "cache/victim.txt")
	result, err := ScanCandidates(root, ScanOptions{MinAgeDays: 30})
	if err != nil || len(result.Candidates) != 1 {
		t.Fatalf("scan failed: %v %+v", err, result)
	}
	candidate := result.Candidates[0]
	p := plan.FromCandidates(result.Candidates, root, "local-agent", "cli", nil, 500, 1<<30, time.Now())
	executor, err := NewQuarantineExecutor(filepath.Join(root, "quarantine"))
	if err != nil {
		t.Fatal(err)
	}
	return executor, p, candidate
}

func approve(t *testing.T, p plan.Plan) (plan.Grant, *plan.Authority) {
	t.Helper()
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
	return grant, authority
}

func requestFor(t *testing.T, action, path, planID, candidateID string) *protocol.Request {
	t.Helper()
	req, err := protocol.NewRequest(action, map[string]any{
		"path": path, "plan_id": planID, "candidate_id": candidateID,
	})
	if err != nil {
		t.Fatal(err)
	}
	return req
}

func TestQuarantineRestoreRoundTrip(t *testing.T) {
	executor, p, candidate := quarantineFixture(t)
	grant, _ := approve(t, p)

	before, _ := os.Stat(candidate.Path)
	result, err := executor.Execute(
		requestFor(t, "filesystem.quarantine", candidate.Path, p.PlanID, candidate.CandidateID),
		p, grant,
	)
	if err != nil {
		t.Fatalf("quarantine failed: %v", err)
	}
	if result.Status != "quarantined" || result.BytesMoved != candidate.SizeBytes {
		t.Fatalf("unexpected result: %+v", result)
	}
	if _, err := os.Lstat(candidate.Path); !os.IsNotExist(err) {
		t.Fatal("source still present after quarantine")
	}
	if _, err := os.Stat(filepath.Join(executor.Dir, p.PlanID, candidate.CandidateID, "meta.json")); err != nil {
		t.Fatalf("sidecar missing: %v", err)
	}

	restoreGrant, _ := approve(t, p)
	restored, err := executor.Execute(
		requestFor(t, "filesystem.restore", candidate.Path, p.PlanID, candidate.CandidateID),
		p, restoreGrant,
	)
	if err != nil {
		t.Fatalf("restore failed: %v", err)
	}
	if restored.Status != "restored" {
		t.Fatalf("unexpected restore result: %+v", restored)
	}
	after, err := os.Stat(candidate.Path)
	if err != nil {
		t.Fatalf("file not restored: %v", err)
	}
	if after.Mode() != before.Mode() || after.Size() != before.Size() || !after.ModTime().Equal(before.ModTime()) {
		t.Fatalf("identity changed across round trip: before=%v after=%v", before, after)
	}
	content, _ := os.ReadFile(candidate.Path)
	if string(content) != "payload" {
		t.Fatalf("content changed: %q", content)
	}
}

func TestExecutorRefusesChangedTarget(t *testing.T) {
	executor, p, candidate := quarantineFixture(t)
	grant, _ := approve(t, p)
	if err := os.WriteFile(candidate.Path, []byte("tampered"), 0o640); err != nil {
		t.Fatal(err)
	}
	_, err := executor.Execute(
		requestFor(t, "filesystem.quarantine", candidate.Path, p.PlanID, candidate.CandidateID),
		p, grant,
	)
	if err == nil || !strings.Contains(err.Error(), "changed") {
		t.Fatalf("expected target_changed, got %v", err)
	}
	if _, statErr := os.Stat(candidate.Path); statErr != nil {
		t.Fatal("source moved despite refusal")
	}
}

func TestExecutorRefusesWrongPathAndReplay(t *testing.T) {
	executor, p, candidate := quarantineFixture(t)
	grant, _ := approve(t, p)
	req := requestFor(t, "filesystem.quarantine", candidate.Path, p.PlanID, candidate.CandidateID)
	req.Typed = &protocol.FilesystemQuarantineParams{PlanTargetParams: protocol.PlanTargetParams{
		Path: candidate.Path + "x", PlanID: p.PlanID, CandidateID: candidate.CandidateID,
	}}
	if _, err := executor.Execute(req, p, grant); err == nil {
		t.Fatal("redirected path accepted")
	}
	if _, err := executor.Execute(
		requestFor(t, "filesystem.quarantine", candidate.Path, p.PlanID, candidate.CandidateID),
		p, grant,
	); err != nil {
		t.Fatal(err)
	}
	if _, err := executor.Execute(
		requestFor(t, "filesystem.quarantine", candidate.Path, p.PlanID, candidate.CandidateID),
		p, grant,
	); err == nil {
		t.Fatal("replayed quarantine accepted")
	}
}

func TestExecutorRefusesSymlinkAndExpiredGrant(t *testing.T) {
	root := t.TempDir()
	target := oldFile(t, root, "cache/real.txt")
	link := filepath.Join(root, "cache", "link.txt")
	if err := os.Symlink(target, link); err != nil {
		t.Skip("symlinks unavailable")
	}
	result, _ := ScanCandidates(root, ScanOptions{MinAgeDays: 30})
	if len(result.Candidates) != 1 {
		t.Skip("symlink was scanned")
	}
	candidate := result.Candidates[0]
	p := plan.FromCandidates(result.Candidates, root, "local-agent", "cli", nil, 500, 1<<30, time.Now())
	executor, _ := NewQuarantineExecutor(filepath.Join(root, "q"))
	grant, _ := approve(t, p)
	grant.ExpiresAt = model.Timestamp{Time: time.Now().Add(-time.Second)}
	if _, err := executor.Execute(
		requestFor(t, "filesystem.quarantine", candidate.Path, p.PlanID, candidate.CandidateID),
		p, grant,
	); err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("expired grant accepted: %v", err)
	}
}

func TestScanRefusesProtectedRoots(t *testing.T) {
	if _, err := ScanCandidates("/proc", ScanOptions{MinAgeDays: 0}); err == nil {
		t.Fatal("protected root /proc was accepted")
	}
	if _, err := ScanCandidates("/etc", ScanOptions{MinAgeDays: 0}); err == nil {
		t.Fatal("protected root /etc was accepted")
	}
}
