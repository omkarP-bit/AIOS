// Package config reads the same AIOS_* environment the Python build used.
package config

import (
	"bufio"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Settings is the runtime configuration.
type Settings struct {
	APIHost        string
	APIPort        int
	ProcRoot       string
	SysRoot        string
	PolicyDir      string
	OPABinary      string
	OPATimeout     time.Duration
	MaxReadBytes   int
	MaxDirEntries  int
	QuarantineDir  string
	LedgerPath     string
	ApprovalSecret string
	ApprovalTTL    time.Duration
	APIURL         string
}

// Default returns the documented defaults.
func Default() Settings {
	home, _ := os.UserHomeDir()
	return Settings{
		APIHost: "127.0.0.1", APIPort: 8000,
		ProcRoot: "/proc", SysRoot: "/sys",
		PolicyDir: "aios/policies", OPABinary: "opa", OPATimeout: 2 * time.Second,
		MaxReadBytes: 1 << 20, MaxDirEntries: 2000,
		QuarantineDir: filepath.Join(home, ".local", "state", "aios", "quarantine"),
		LedgerPath:    filepath.Join(home, ".local", "state", "aios", "ledger.jsonl"),
		ApprovalTTL:   15 * time.Minute,
		APIURL:        "http://127.0.0.1:8000",
	}
}

// Load reads .env (if present) then the environment.
func Load() Settings {
	s := Default()
	loadDotEnv(".env")
	s.APIHost = env("AIOS_API_HOST", s.APIHost)
	s.APIPort = envInt("AIOS_API_PORT", s.APIPort)
	s.ProcRoot = env("AIOS_PROC_ROOT", s.ProcRoot)
	s.SysRoot = env("AIOS_SYS_ROOT", s.SysRoot)
	s.PolicyDir = env("AIOS_POLICY_DIR", s.PolicyDir)
	s.OPABinary = env("AIOS_OPA_BINARY", s.OPABinary)
	s.OPATimeout = time.Duration(envInt("AIOS_OPA_TIMEOUT_S", int(s.OPATimeout/time.Second))) * time.Second
	s.MaxReadBytes = envInt("AIOS_MAX_READ_BYTES", s.MaxReadBytes)
	s.MaxDirEntries = envInt("AIOS_MAX_DIR_ENTRIES", s.MaxDirEntries)
	s.QuarantineDir = envPath("AIOS_QUARANTINE_DIR", s.QuarantineDir)
	s.LedgerPath = envPath("AIOS_LEDGER_PATH", s.LedgerPath)
	s.ApprovalSecret = env("AIOS_APPROVAL_SECRET", "")
	s.ApprovalTTL = time.Duration(envInt("AIOS_APPROVAL_TTL_S", int(s.ApprovalTTL/time.Second))) * time.Second
	s.APIURL = env("AIOS_API_URL", s.APIURL)
	return s
}

func env(key, fallback string) string {
	if value, ok := os.LookupEnv(key); ok && value != "" {
		return value
	}
	return fallback
}

func envPath(key, fallback string) string {
	value := env(key, fallback)
	if value == "~" || strings.HasPrefix(value, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			return filepath.Join(home, strings.TrimPrefix(value, "~/"))
		}
	}
	return value
}

func envInt(key string, fallback int) int {
	value, ok := os.LookupEnv(key)
	if !ok || value == "" {
		return fallback
	}
	parsed, err := strconv.Atoi(value)
	if err != nil {
		return fallback
	}
	return parsed
}

func loadDotEnv(path string) {
	file, err := os.Open(path)
	if err != nil {
		return
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(strings.TrimPrefix(key, "export "))
		value = strings.TrimSpace(value)
		value = strings.Trim(value, `"'`)
		if _, exists := os.LookupEnv(key); exists {
			continue
		}
		_ = os.Setenv(key, value)
	}
}
