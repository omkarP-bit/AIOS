package gateway

import (
	"os"
	"path/filepath"
	"testing"

	"aios/internal/protocol"
)

func TestFileContentIsTaggedT4(t *testing.T) {
	path := filepath.Join(t.TempDir(), "notes.txt")
	if err := os.WriteFile(path, []byte("hostile bytes"), 0o600); err != nil {
		t.Fatal(err)
	}
	req, err := protocol.NewRequest("filesystem.read", map[string]any{"path": path})
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := New("/proc", "/sys", "").Execute(req)
	if err != nil {
		t.Fatal(err)
	}
	if envelope.TrustDomain != "T4" || envelope.Trusted() {
		t.Fatalf("file content must be untrusted: %+v", envelope)
	}
	data, ok := envelope.Data.(map[string]any)
	if !ok || data["content"] != "hostile bytes" {
		t.Fatalf("unexpected payload: %+v", envelope.Data)
	}
}

func TestGatewayIsAReadOnlyWhitelist(t *testing.T) {
	gw := New("/proc", "/sys", "")
	for _, action := range []string{"filesystem.quarantine", "filesystem.restore", "filesystem.purge", "shell.exec"} {
		if gw.Supports(action) {
			t.Fatalf("%s must not be reachable through the gateway", action)
		}
	}
	if !gw.Supports("process.list") || !gw.Supports("filesystem.cleanup_scan") || !gw.Supports("filesystem.usage") {
		t.Fatal("read-only actions missing from the gateway")
	}
}

func TestReadOutsideTheWhitelistIsRefused(t *testing.T) {
	req, err := protocol.NewRequest("filesystem.quarantine", map[string]any{
		"path": "/tmp/victim", "plan_id": "plan-0123456789abcdef01234567",
		"candidate_id": "c-0123456789abcdef",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := New("/proc", "/sys", "").Execute(req); err == nil {
		t.Fatal("gateway executed a mutation action")
	}
}
