package plan

import (
	"testing"
	"time"
)

// ASI02-031: cleanup plan state is engine-owned. A caller cannot overwrite the
// stored body, replay approval for a different hash, or move a terminal plan.
func TestCleanupRegistryGuardsApproval(t *testing.T) {
	now := time.Now()
	base, err := NewCleanupPlan(
		"agent", "session",
		Criteria{Root: "/tmp/work", MinAgeDays: 1, MaxResults: 10},
		[]Entry{{Realpath: "/tmp/work/a.log", Size: 1}},
		time.Minute, now,
	)
	if err != nil {
		t.Fatal(err)
	}
	registry := NewCleanupRegistry(time.Minute)
	registry.Put(base, now)

	if _, err := registry.Get(base.PlanID, now); err != nil {
		t.Fatal(err)
	}
	if _, err := registry.Get("plan-unknown", now); err == nil {
		t.Fatal("unknown plan was returned")
	}

	token := Token{PlanID: base.PlanID, PlanHash: base.PlanHash, Nonce: "n"}
	if err := registry.SetApproval(base.PlanID, "sha256:wrong", token, now); err == nil {
		t.Fatal("approval accepted a mismatched hash")
	}
	if err := registry.SetApproval(base.PlanID, base.PlanHash, token, now); err != nil {
		t.Fatal(err)
	}
	if _, err := registry.SetStatus(base.PlanID, base.PlanHash, CleanupApproved, now); err != nil {
		t.Fatalf("approve transition: %v", err)
	}
	if _, err := registry.SetStatus(base.PlanID, base.PlanHash, CleanupApproved, now); err == nil {
		t.Fatal("a plan was approved twice")
	}

	// The returned copy cannot mutate stored state.
	stored, err := registry.Get(base.PlanID, now)
	if err != nil {
		t.Fatal(err)
	}
	stored.Entries[0].Size++
	again, _ := registry.Get(base.PlanID, now)
	if again.Entries[0].Size != base.Entries[0].Size {
		t.Fatal("registry leaked a mutable plan body")
	}

	// An expired plan is pruned from every view.
	later := now.Add(2 * time.Minute)
	if _, err := registry.Get(base.PlanID, later); err == nil {
		t.Fatal("expired plan was returned")
	}
	if len(registry.List(later)) != 0 {
		t.Fatal("expired plan appeared in the list")
	}
}
