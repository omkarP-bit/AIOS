package plan

import (
	"strings"
	"testing"
	"time"

	"aios/internal/model"
)

const (
	pythonPlanHash = "sha256:1799ac10a6be01dcc9e16d83653c186903ba1cdf1821330093747cd5266bfbdf"
	pythonScope    = "sha256:3bacd62402e3ce67ef3f83cfca0d7614f2b204adea04b18321674a04e2b276e9"
	pythonSig      = "02cb3f38dd7ec08fa72618f2e47bb142ea7848e6389a12bde0ba3f9efd287528"
)

func fixturePlan(t *testing.T) Plan {
	t.Helper()
	created, err := time.Parse(time.RFC3339Nano, "2026-11-15T02:03:04.123456Z")
	if err != nil {
		t.Fatal(err)
	}
	intent := "clean cache"
	return Plan{
		PlanID: "plan-0123456789abcdef01234567", CatalogVersion: "2026-11-13",
		AgentID: "local-agent", SessionID: "cli", Intent: &intent,
		CreatedAt: model.Timestamp{Time: created}, Roots: []string{"/home/u"},
		Limits: Limits{MaxItems: 500, MaxBytes: 10_737_418_240},
		Steps: []Step{{
			StepID: "step-1", Action: "filesystem.quarantine",
			CandidateID: "c-0123456789abcdef", Path: "/home/u/.cache/foo",
			Dev: 2049, Ino: 12345, SizeBytes: 104_857_600,
			MtimeNS: 1_763_000_000_000_000_000, Mode: 33188, UID: 1000,
		}},
		Rollback: []RollbackStep{{
			StepID: "step-1", Action: "filesystem.restore",
			CandidateID: "c-0123456789abcdef", Path: "/home/u/.cache/foo",
		}},
	}
}

// TestHashMatchesPythonReference pins the canonical form to the Python
// implementation. If this breaks, plans approved by one side are unverifiable
// by the other.
func TestHashMatchesPythonReference(t *testing.T) {
	p := fixturePlan(t)
	p.PlanHash = ComputeHash(p)
	if p.PlanHash != pythonPlanHash {
		t.Fatalf("hash = %s, want %s", p.PlanHash, pythonPlanHash)
	}
	if err := p.Validate(); err != nil {
		t.Fatalf("fixture plan invalid: %v", err)
	}
}

func TestHashCoversEveryField(t *testing.T) {
	p := fixturePlan(t)
	p.PlanHash = ComputeHash(p)
	mutations := []func(*Plan){
		func(x *Plan) { x.Steps[0].Path = "/home/u/.cache/bar" },
		func(x *Plan) { x.Steps[0].SizeBytes++ },
		func(x *Plan) { x.Steps[0].Mode++ },
		func(x *Plan) { x.Steps[0].UID++ },
		func(x *Plan) { x.Roots[0] = "/home" },
		func(x *Plan) { x.Limits.MaxItems++ },
		func(x *Plan) { x.AgentID = "other" },
		func(x *Plan) { x.CatalogVersion = "2099-01-01" },
	}
	for i, mutate := range mutations {
		changed := fixturePlan(t)
		changed.PlanHash = p.PlanHash
		mutate(&changed)
		if ComputeHash(changed) == p.PlanHash {
			t.Errorf("mutation %d did not change the hash", i)
		}
		if err := changed.Validate(); err == nil {
			t.Errorf("mutation %d passed validation with the old hash", i)
		}
	}
}

func TestValidateRefusesBadPlans(t *testing.T) {
	base := fixturePlan(t)
	base.PlanHash = ComputeHash(base)
	cases := []func(*Plan){
		func(p *Plan) { p.PlanID = "" },
		func(p *Plan) { p.Steps = nil },
		func(p *Plan) { p.Limits.MaxItems = 0 },
		func(p *Plan) { p.Limits.MaxBytes = 1 },
		func(p *Plan) { p.Roots = nil },
		func(p *Plan) { p.Steps[0].Action = "filesystem.write" },
		func(p *Plan) { p.Steps[0].Action = "system.cpu" },
		func(p *Plan) { p.Steps[0].Path = "" },
	}
	for i, mutate := range cases {
		p := base
		p.Steps = append([]Step(nil), base.Steps...)
		mutate(&p)
		if err := p.Validate(); err == nil {
			t.Errorf("case %d passed validation", i)
		}
	}
}

func TestApprovalParityAndLifecycle(t *testing.T) {
	p := fixturePlan(t)
	p.PlanHash = ComputeHash(p)
	approval, err := NewAuthority([]byte("0123456789abcdef0123456789abcdef"), 15*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := scopeDigest(p)
	if err != nil {
		t.Fatal(err)
	}
	if digest != pythonScope {
		t.Fatalf("scope digest = %s, want %s", digest, pythonScope)
	}
	approvedAt, _ := time.Parse(time.RFC3339Nano, "2026-11-15T02:04:00Z")
	expiresAt, _ := time.Parse(time.RFC3339Nano, "2026-11-15T02:19:00Z")
	token := Token{
		TokenVersion: 1, PlanID: p.PlanID, PlanHash: p.PlanHash,
		ApprovedBy: "operator", ApprovedAt: model.Timestamp{Time: approvedAt},
		ExpiresAt: model.Timestamp{Time: expiresAt},
		Nonce:     "abcdefghijklmnopqrstuvwx", ScopeDigest: digest,
	}
	signature, err := approval.sign(token.payload())
	if err != nil {
		t.Fatal(err)
	}
	if signature != pythonSig {
		t.Fatalf("signature = %s, want %s", signature, pythonSig)
	}
	token.Signature = signature

	now := approvedAt.Add(time.Minute)
	first, err := approval.Verify(token, p, true, now)
	if err != nil {
		t.Fatalf("valid token rejected: %v", err)
	}
	if first.PlanHash != p.PlanHash || first.ApprovedBy != "operator" {
		t.Fatalf("unexpected grant: %+v", first)
	}
	if _, err := approval.Verify(token, p, true, now); err == nil {
		t.Fatal("replayed token accepted")
	}

	// A fresh authority to test expiry, binding, and tampering.
	fresh, _ := NewAuthority([]byte("0123456789abcdef0123456789abcdef"), 15*time.Minute)
	if _, err := fresh.Verify(token, p, false, expiresAt); err == nil {
		t.Fatal("expired token accepted")
	}
	other := fixturePlan(t)
	other.PlanID = "plan-ffffffffffffffffffffffff"
	other.PlanHash = ComputeHash(other)
	if _, err := fresh.Verify(token, other, false, now); err == nil {
		t.Fatal("token accepted for a different plan")
	}
	tampered := token
	tampered.ApprovedBy = "mallory"
	if _, err := fresh.Verify(tampered, p, false, now); err == nil {
		t.Fatal("tampered token accepted")
	}
}

func TestMintProducesVerifiableToken(t *testing.T) {
	p := fixturePlan(t)
	p.PlanHash = ComputeHash(p)
	approval, err := NewAuthority([]byte("a-long-enough-secret"), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	token, err := approval.Mint(p, "operator", 0)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(token.Signature, "") || len(token.Signature) != 64 {
		t.Fatalf("unexpected signature: %q", token.Signature)
	}
	now := time.Now()
	if _, err := approval.Verify(token, p, true, now); err != nil {
		t.Fatalf("minted token failed verification: %v", err)
	}
	if _, err := NewAuthority([]byte("short"), time.Minute); err == nil {
		t.Fatal("short secret accepted")
	}
}

func TestFromCandidatesEnforcesMaxItems(t *testing.T) {
	candidates := []model.Candidate{
		{CandidateID: "c-aaaaaaaaaaaaaaaa", Path: "/home/u/a", SizeBytes: 10},
		{CandidateID: "c-bbbbbbbbbbbbbbbb", Path: "/home/u/b", SizeBytes: 20},
		{CandidateID: "c-cccccccccccccccc", Path: "/home/u/c", SizeBytes: 30},
	}
	p := FromCandidates(candidates, "/home/u", "local-agent", "cli", nil, 2, 1000, time.Now())
	if len(p.Steps) != 2 {
		t.Fatalf("steps = %d, want 2", len(p.Steps))
	}
	if p.Steps[0].StepID != "step-1" || p.Steps[1].StepID != "step-2" {
		t.Fatalf("unexpected step ids: %+v", p.Steps)
	}
	if len(p.Rollback) != 2 || p.Rollback[0].Action != "filesystem.restore" {
		t.Fatalf("unexpected rollback: %+v", p.Rollback)
	}
	if p.PlanID[:5] != "plan-" || len(p.PlanID) != 29 {
		t.Fatalf("unexpected plan id %q", p.PlanID)
	}
	if p.PlanHash != ComputeHash(p) {
		t.Fatal("hash not bound at construction")
	}
}
