package config

import (
	"os"
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

func TestDotEnvPathHonoursTheExplicitOverride(t *testing.T) {
	t.Setenv("AIOS_ENV_FILE", "/tmp/explicit.env")
	if got := dotEnvPath(); got != "/tmp/explicit.env" {
		t.Fatalf("dotEnvPath = %q, want the explicit override", got)
	}
}

func TestDotEnvPathPrefersTheStateFileOverTheWorkingDirectory(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("AIOS_ENV_FILE", "")
	want := filepath.Join(home, ".aios", ".env")
	if got := dotEnvPath(); got != ".env" {
		t.Fatalf("dotEnvPath without a state file = %q, want .env", got)
	}
	if err := os.MkdirAll(filepath.Dir(want), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(want, []byte("AIOS_MODEL_PROVIDER=groq\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := dotEnvPath(); got != want {
		t.Fatalf("dotEnvPath = %q, want %q", got, want)
	}
}
