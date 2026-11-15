package config

import (
	"path/filepath"
	"testing"
)

func TestLoadExpandsHomeInStatePaths(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("AIOS_QUARANTINE_DIR", "~/quarantine")
	t.Setenv("AIOS_LEDGER_PATH", "~/state/ledger.jsonl")
	settings := Load()
	if want := filepath.Join(home, "quarantine"); settings.QuarantineDir != want {
		t.Fatalf("quarantine: got %q want %q", settings.QuarantineDir, want)
	}
	if want := filepath.Join(home, "state", "ledger.jsonl"); settings.LedgerPath != want {
		t.Fatalf("ledger: got %q want %q", settings.LedgerPath, want)
	}
}

func TestLoadKeepsExplicitPaths(t *testing.T) {
	t.Setenv("AIOS_QUARANTINE_DIR", "/tmp/explicit-q")
	t.Setenv("AIOS_LEDGER_PATH", "/tmp/explicit-ledger.jsonl")
	settings := Load()
	if settings.QuarantineDir != "/tmp/explicit-q" {
		t.Fatalf("quarantine: %q", settings.QuarantineDir)
	}
	if settings.LedgerPath != "/tmp/explicit-ledger.jsonl" {
		t.Fatalf("ledger: %q", settings.LedgerPath)
	}
}
