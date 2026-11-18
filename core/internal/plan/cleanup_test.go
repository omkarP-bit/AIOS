package plan

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"aios/internal/model"
)

func cleanupFixture(t *testing.T) CleanupPlan {
	t.Helper()
	now := time.Date(2026, 11, 18, 10, 0, 0, 0, time.UTC)
	p, err := NewCleanupPlan(
		"local-agent", "session-1",
		Criteria{Root: "/tmp/work", MinAgeDays: 30, MinSizeBytes: 1024, Extensions: []string{".log"}, MaxResults: 100},
		[]Entry{
			{Realpath: "/tmp/work/b.log", Size: 2048, Mtime: 100, Inode: 2, Device: 1, Owner: 1000},
			{Realpath: "/tmp/work/a.log", Size: 4096, Mtime: 200, Inode: 3, Device: 1, Owner: 1000},
		},
		15*time.Minute, now,
	)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestCleanupPlanHashCoversEveryApprovedField(t *testing.T) {
	base := cleanupFixture(t)
	other := base
	other.Entries = append([]Entry(nil), base.Entries...)
	other.Entries[0].Size++
	mutations := map[string]CleanupPlan{
		"plan_id":     func() CleanupPlan { p := base; p.PlanID = "plan-other"; return p }(),
		"session_id":  func() CleanupPlan { p := base; p.SessionID = "session-2"; return p }(),
		"agent_id":    func() CleanupPlan { p := base; p.AgentID = "other-agent"; return p }(),
		"root":        func() CleanupPlan { p := base; p.Root = "/tmp/other"; return p }(),
		"criteria":    func() CleanupPlan { p := base; p.Criteria.MinAgeDays = 31; return p }(),
		"entries":     other,
		"file_count":  func() CleanupPlan { p := base; p.FileCount = 99; return p }(),
		"total_bytes": func() CleanupPlan { p := base; p.TotalBytes = 99; return p }(),
		"created_at": func() CleanupPlan {
			p := base
			p.CreatedAt = model.Timestamp{Time: p.CreatedAt.Add(time.Second)}
			return p
		}(),
		"expires_at": func() CleanupPlan {
			p := base
			p.ExpiresAt = model.Timestamp{Time: p.ExpiresAt.Add(time.Second)}
			return p
		}(),
	}
	for field, changed := range mutations {
		hash, err := ComputeCleanupHash(changed)
		if err != nil {
			t.Fatal(err)
		}
		if hash == base.PlanHash {
			t.Errorf("hash did not change when %s changed", field)
		}
	}
	status := base
	status.Status = CleanupApproved
	if got, err := ComputeCleanupHash(status); err != nil || got != base.PlanHash {
		t.Fatalf("status must not change hash: %q %v", got, err)
	}
}

func TestCleanupPlanIsDeterministic(t *testing.T) {
	p := cleanupFixture(t)
	recomputed, err := ComputeCleanupHash(p)
	if err != nil {
		t.Fatal(err)
	}
	if recomputed != p.PlanHash {
		t.Fatalf("recomputed hash %q differs from stored hash %q", recomputed, p.PlanHash)
	}
	if p.Entries[0].Realpath != "/tmp/work/a.log" {
		t.Fatalf("entries are not sorted: %+v", p.Entries)
	}
}

func TestCleanupPlanRejectsUnsafeCriteria(t *testing.T) {
	now := time.Now()
	cases := []Criteria{
		{Root: "relative", MaxResults: 1},
		{Root: "", MaxResults: 1},
		{Root: "/tmp/x\x00y", MaxResults: 1},
		{Root: "/tmp/x", MinAgeDays: -1, MaxResults: 1},
		{Root: "/tmp/x", MinSizeBytes: -1, MaxResults: 1},
		{Root: "/tmp/x", MaxResults: 0},
	}
	for _, c := range cases {
		if _, err := NewCleanupPlan("agent", "session", c, nil, time.Minute, now); err == nil {
			t.Errorf("accepted unsafe criteria: %+v", c)
		}
	}
}

func TestCleanupPlanTransitions(t *testing.T) {
	legal := [][2]CleanupStatus{
		{CleanupPendingApproval, CleanupApproved},
		{CleanupPendingApproval, CleanupRejected},
		{CleanupPendingApproval, CleanupExpired},
		{CleanupApproved, CleanupExecuted},
		{CleanupApproved, CleanupExpired},
	}
	for _, edge := range legal {
		if err := AssertCleanupTransition(edge[0], edge[1]); err != nil {
			t.Errorf("rejected legal transition %v: %v", edge, err)
		}
	}
	illegal := [][2]CleanupStatus{
		{CleanupExecuted, CleanupApproved},
		{CleanupRejected, CleanupExecuted},
		{CleanupPendingApproval, CleanupExecuted},
		{CleanupExpired, CleanupApproved},
	}
	for _, edge := range illegal {
		if err := AssertCleanupTransition(edge[0], edge[1]); err == nil {
			t.Errorf("accepted illegal transition %v", edge)
		}
	}
}

func TestCleanupSummaryHasNoApprovalFlags(t *testing.T) {
	raw, err := json.Marshal(cleanupFixture(t).Summary())
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	for _, forbidden := range []string{"approved", "path_in_plan", "entries", "agent_id", "plan_hash_is"} {
		if strings.Contains(text, forbidden) {
			t.Errorf("AI-visible summary contains %q: %s", forbidden, text)
		}
	}
}
