package filesafety

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func testRules(t *testing.T, home string) Rules {
	t.Helper()
	rules, err := NewRules(home, nil)
	if err != nil {
		t.Fatal(err)
	}
	return rules
}

func oldFile(t *testing.T, root, name string) string {
	t.Helper()
	path := filepath.Join(root, name)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("payload"), 0o600); err != nil {
		t.Fatal(err)
	}
	old := time.Now().AddDate(0, 0, -40)
	if err := os.Chtimes(path, old, old); err != nil {
		t.Fatal(err)
	}
	return path
}

// ASI02-014: protected paths are applied after realpath expansion. Policy may
// add entries but cannot remove the Go hard floor.
func TestProtectedPathsSurvivePolicyEdits(t *testing.T) {
	home := t.TempDir()
	rules, err := NewRules(home, []string{"/tmp/extra-protected"})
	if err != nil {
		t.Fatal(err)
	}
	cases := []string{
		filepath.Join(home, ".ssh", "id_rsa"),
		filepath.Join(home, ".gnupg"),
		filepath.Join(home, ".config", "aios"),
		filepath.Join(home, ".aios", "state"),
		filepath.Join(home, "repo", ".git", "config"),
		filepath.Join(home, "repo", "sub", ".git", "objects"),
		"/etc/passwd", "/boot/vmlinuz", "/usr/bin/python3", "/var/log/syslog",
		"/root/.bashrc", "/proc/self/environ", "/sys/kernel", "/tmp/extra-protected/a.log",
	}
	for _, path := range cases {
		if !rules.IsProtected(path) {
			t.Errorf("path was not protected: %s", path)
		}
	}
	if rules.IsProtected(filepath.Join(home, "Downloads", "old.log")) {
		t.Fatal("ordinary file was protected")
	}
}

func TestPolicyDataListsTheHardFloor(t *testing.T) {
	repoData := filepath.Join("..", "..", "..", "aios", "policies", "data.json")
	rules, err := Load(filepath.Dir(repoData))
	if err != nil {
		t.Fatal(err)
	}
	for _, pattern := range Floor {
		if pattern == "**/.git" {
			if !rules.gitShield {
				t.Fatal("policy data lost the .git shield")
			}
			continue
		}
		want := pattern
		if strings.HasPrefix(pattern, "~/") {
			want = filepath.Join(mustHome(t), strings.TrimPrefix(pattern, "~/"))
		}
		found := false
		for _, resolved := range rules.prefixes {
			if resolved == want {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("policy data is missing floor entry %q", pattern)
		}
	}
}

func mustHome(t *testing.T) string {
	t.Helper()
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	return home
}

// ASI02-015: a symlink in any parent directory is refused before a file can be
// moved, even when the lexical path is inside the approved root.
func TestValidateTargetRefusesSymlinkEscape(t *testing.T) {
	home := t.TempDir()
	root := t.TempDir()
	outside := t.TempDir()
	path := oldFile(t, outside, "old.log")
	if err := os.Symlink(outside, filepath.Join(root, "link")); err != nil {
		t.Fatal(err)
	}
	trapped := filepath.Join(root, "link", "old.log")
	rules := testRules(t, home)
	if _, err := rules.ValidateTarget(trapped, root, uint32(os.Getuid())); err == nil {
		t.Fatal("symlinked parent was accepted")
	}
	if _, err := rules.ValidateTarget(path, root, uint32(os.Getuid())); err == nil {
		t.Fatal("file outside root was accepted")
	}
}

// ASI02-016: protected paths, the root itself, directories, foreign owners,
// and symlinks are all refused at execution time, not just at scan time.
func TestValidateTargetRejectsUnsafeTargets(t *testing.T) {
	home := t.TempDir()
	root := t.TempDir()
	target := oldFile(t, root, "cache/old.log")
	link := filepath.Join(root, "escape")
	if err := os.Symlink(filepath.Join(home, ".ssh"), link); err != nil {
		t.Fatal(err)
	}
	protected := oldFile(t, home, ".ssh/id_rsa")
	rules := testRules(t, home)
	uid := uint32(os.Getuid())
	cases := map[string]struct {
		path, root string
		uid        uint32
	}{
		"protected realpath": {protected, root, uid},
		"root itself":        {root, root, uid},
		"directory":          {filepath.Join(root, "cache"), root, uid},
		"foreign owner":      {target, root, uid + 1},
		"missing":            {filepath.Join(root, "missing.log"), root, uid},
	}
	for name, tc := range cases {
		if _, err := rules.ValidateTarget(tc.path, tc.root, tc.uid); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
	if _, err := rules.ValidateTarget(filepath.Join(link, "id_rsa"), root, uid); err == nil {
		t.Fatal("protected realpath through symlink was accepted")
	}
}

func TestValidateTargetCapturesIdentity(t *testing.T) {
	home := t.TempDir()
	root := t.TempDir()
	path := oldFile(t, root, "a.log")
	rules := testRules(t, home)
	target, err := rules.ValidateTarget(path, root, uint32(os.Getuid()))
	if err != nil {
		t.Fatal(err)
	}
	if target.Realpath != path || target.Size != 7 || target.Inode == 0 || target.Device == 0 {
		t.Fatalf("incomplete target identity: %+v", target)
	}
	all, err := rules.ValidatePlan([]string{path}, root, uint32(os.Getuid()))
	if err != nil || len(all) != 1 {
		t.Fatalf("plan validation failed: %v %+v", err, all)
	}
}
