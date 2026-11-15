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
