package ledger

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDurableLedgerReloadsHistory(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ledger.jsonl")
	first, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, state := range []string{"VALIDATED", "AUTHORIZED", "COMPLETED"} {
		if err := first.Record(Entry{ActionID: "act-1", Action: "system.cpu", State: state}); err != nil {
			t.Fatal(err)
		}
	}
	second, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	states := second.States("act-1")
	if len(states) != 3 || states[2] != "COMPLETED" {
		t.Fatalf("unexpected history: %v", states)
	}
}

func TestLoadSkipsAPartialTrailingLine(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ledger.jsonl")
	if err := os.WriteFile(path, []byte(
		`{"action_id":"act-1","action":"system.cpu","state":"COMPLETED"}`+"\n"+`{"action_id":`+"\n",
	), 0o600); err != nil {
		t.Fatal(err)
	}
	audit, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := audit.States("act-1"); len(got) != 1 || got[0] != "COMPLETED" {
		t.Fatalf("unexpected states: %v", got)
	}
}

// ASI02-023: a failed durable write must not leave a phantom AUTHORIZED row in
// the in-memory trail. The engine relies on this to fail closed.
func TestFailedRecordDoesNotEnterMemory(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ledger.jsonl")
	audit, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(path, path+".saved"); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := audit.Record(Entry{ActionID: "act-1", State: "AUTHORIZED"}); err == nil {
		t.Fatal("expected the ledger write to fail")
	}
	if got := audit.Entries(); len(got) != 0 {
		t.Fatalf("failed write entered the memory trail: %+v", got)
	}
}

func TestMemoryLedgerWritesNoFile(t *testing.T) {
	audit, err := New("")
	if err != nil {
		t.Fatal(err)
	}
	if err := audit.Record(Entry{ActionID: "act-2", Action: "system.cpu", State: "VALIDATED"}); err != nil {
		t.Fatal(err)
	}
	if len(audit.Entries()) != 1 {
		t.Fatal("memory ledger lost the entry")
	}
}
