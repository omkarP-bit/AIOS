package capability

import (
	"strings"
	"testing"
	"time"
)

func TestPathScopeSemantics(t *testing.T) {
	downloads := []string{"/home/user/Downloads/*"}
	cases := []struct {
		path string
		want bool
	}{
		{"/home/user/Downloads/report.pdf", true},
		{"/home/user/Downloads/sub/deep.pdf", true},
		{"/home/user/Downloads", false},
		{"/home/user/.ssh/id_rsa", false},
		{"/home/user/Downloadsx", false},
		{"/etc/shadow", false},
		{"/home/user/Downloads/../.ssh/id_rsa", false},
		{"/home/user/Downloads/../../etc/shadow", false},
	}
	for _, tc := range cases {
		if got := PathInScope(tc.path, downloads); got != tc.want {
			t.Errorf("PathInScope(%q) = %v, want %v", tc.path, got, tc.want)
		}
	}
}

func TestPathTraversalCollapses(t *testing.T) {
	patterns := []string{"/srv/allowed/*"}
	for _, attack := range []string{
		"/srv/allowed/../../etc/shadow",
		"/srv/allowed/../secret",
		"/srv/allowed/./../secret",
	} {
		if PathInScope(attack, patterns) {
			t.Errorf("traversal %q was in scope", attack)
		}
	}
	if PathInScope("/srv/allowed/file", nil) {
		t.Error("empty scope matched")
	}
}

func TestDoubleStarAbsorbsSegments(t *testing.T) {
	scope := []string{"/var/log/**"}
	if !PathInScope("/var/log/syslog", scope) {
		t.Error("direct child not matched")
	}
	if !PathInScope("/var/log/nginx/access.log", scope) {
		t.Error("nested child not matched")
	}
	if PathInScope("/var/lib/secret", scope) {
		t.Error("sibling matched")
	}
}

func TestSegmentGlobDoesNotCrossSeparator(t *testing.T) {
	if !PathInScope("/home/user", []string{"/home/u*"}) {
		t.Error("segment glob should match one segment")
	}
	if PathInScope("/home/user/.ssh/id_rsa", []string{"/home/u*"}) {
		t.Error("segment glob crossed a separator")
	}
}

func TestWildcardPrefixIsBroadByDesign(t *testing.T) {
	// Documented matcher semantics: /home/* is everything under /home. The
	// operator grant path rejects this pattern as too broad, so the matcher
	// must not silently narrow it either.
	if !PathInScope("/home/user/.ssh/id_rsa", []string{"/home/*"}) {
		t.Error("trailing /* should match strictly below the prefix")
	}
}

// ASI02-006: the grant pattern validator rejects root wildcards, home
// expansion, relative paths, NUL, and traversal before any grant is installed.
func TestGrantPatternValidation(t *testing.T) {
	invalid := []string{"/*", "/home/*", "/", "relative", "~/Downloads", "/tmp/x\x00y", "/tmp/../etc", "/tmp/\x1b[2J"}
	for _, pattern := range invalid {
		if err := ValidateScopePattern(pattern); err == nil {
			t.Errorf("accepted invalid grant pattern %q", pattern)
		}
	}
	valid := []string{"/home/alice/Downloads/*", "/home/alice/Downloads", "/var/log/**"}
	for _, pattern := range valid {
		if err := ValidateScopePattern(pattern); err != nil {
			t.Errorf("rejected valid grant pattern %q: %v", pattern, err)
		}
	}
}

// ASI03-001: filesystem.trash is not granted by default and PATH grants need
// an explicit scope and a resolved target.
func TestTrashGrantIsNotDefault(t *testing.T) {
	m := NewManager()
	if check := m.Check("local-agent", "filesystem.trash", "/tmp/x", time.Now()); check.Allowed {
		t.Fatal("trash was granted by default")
	}
	if _, err := m.GrantScoped("local-agent", "filesystem.trash", nil, nil, "operator", "test"); err == nil {
		t.Fatal("PATH grant with empty scope was accepted")
	}
	if _, err := m.GrantScoped("local-agent", "filesystem.delete", []string{"/tmp/*"}, nil, "operator", "test"); err == nil {
		t.Fatal("forbidden action was granted")
	}
	expires := time.Now().Add(30 * time.Minute)
	cap, err := m.GrantScoped("local-agent", "filesystem.trash", []string{"/home/alice/Downloads/*"}, &expires, "operator", "cleanup")
	if err != nil {
		t.Fatal(err)
	}
	if cap.ExpiresAt == nil || !cap.ExpiresAt.Equal(expires) {
		t.Fatalf("expiry not attached: %+v", cap)
	}
	if !m.Check("local-agent", "filesystem.trash", "/home/alice/Downloads/old.log", time.Now()).Allowed {
		t.Fatal("scoped trash grant denied in-scope target")
	}
	if m.Check("local-agent", "filesystem.trash", "", time.Now()).Allowed {
		t.Fatal("unresolved target was authorized")
	}
	if m.Check("local-agent", "filesystem.trash", "/etc/shadow", time.Now()).Allowed {
		t.Fatal("out-of-scope target was authorized")
	}
}

// ASI03-002: a grant on the deprecated name authorizes the current operation
// and vice versa, without changing the risk of the requested action.
func TestGrantAliasesCoverTrash(t *testing.T) {
	m := EmptyManager()
	m.Grant("local-agent", Capability{Action: "filesystem.quarantine", Scope: []string{"/tmp/work/*"}})
	if !m.Check("local-agent", "filesystem.trash", "/tmp/work/a.log", time.Now()).Allowed {
		t.Fatal("legacy grant did not cover filesystem.trash")
	}
	m.Revoke("local-agent", "filesystem.quarantine")
	if m.Check("local-agent", "filesystem.trash", "/tmp/work/a.log", time.Now()).Allowed {
		t.Fatal("revoking the legacy name did not revoke trash")
	}
}

func TestPidScopeForms(t *testing.T) {
	cases := []struct {
		pid      int
		patterns []string
		want     bool
	}{
		{4312, []string{"4312"}, true},
		{1500, []string{"1000-2000"}, true},
		{2500, []string{"1000-2000"}, false},
		{7, []string{"1,2,7"}, true},
		{99999, []string{"*"}, true},
		{3, []string{"1", "2"}, false},
		{3, nil, false},
	}
	for _, tc := range cases {
		if got := PIDInScope(tc.pid, tc.patterns); got != tc.want {
			t.Errorf("PIDInScope(%d, %v) = %v, want %v", tc.pid, tc.patterns, got, tc.want)
		}
	}
}

func TestUngrantedActionIsDenied(t *testing.T) {
	m := EmptyManager()
	check := m.Check("local-agent", "process.list", "", time.Now())
	if check.Allowed || !strings.Contains(check.Reason, "deny by default") {
		t.Fatalf("expected deny-by-default, got %+v", check)
	}
}

func TestNoCapabilityImpliesAnother(t *testing.T) {
	m := EmptyManager()
	m.Grant("local-agent", Capability{Action: "process.list"})
	for _, action := range []string{"process.inspect", "filesystem.list", "filesystem.read", "system.cpu"} {
		if m.Check("local-agent", action, "", time.Now()).Allowed {
			t.Errorf("%s was implied by process.list", action)
		}
	}
}

func TestDirectoryGrantDoesNotGrantRead(t *testing.T) {
	m := EmptyManager()
	m.Grant("local-agent", Capability{Action: "filesystem.list", Scope: []string{"/home/user/Downloads/*"}})
	if !m.Check("local-agent", "filesystem.list", "/home/user/Downloads/x", time.Now()).Allowed {
		t.Fatal("list in scope denied")
	}
	if m.Check("local-agent", "filesystem.read", "/home/user/Downloads/x", time.Now()).Allowed {
		t.Fatal("read implied by list")
	}
}

func TestUnknownAgentHasNothing(t *testing.T) {
	m := EmptyManager()
	m.Grant("local-agent", Capability{Action: "process.list"})
	if m.Check("other-agent", "process.list", "", time.Now()).Allowed {
		t.Fatal("unknown agent allowed")
	}
}

func TestScopeEnforcement(t *testing.T) {
	m := EmptyManager()
	m.Grant("local-agent", Capability{Action: "filesystem.read", Scope: []string{"/home/user/Downloads/*"}})
	if check := m.Check("local-agent", "filesystem.read", "/home/user/Downloads/report.pdf", time.Now()); !check.Allowed || check.MatchedCapability == "" {
		t.Fatalf("in-scope read denied: %+v", check)
	}
	check := m.Check("local-agent", "filesystem.read", "/home/user/.ssh/id_rsa", time.Now())
	if check.Allowed || !strings.Contains(check.Reason, "outside every granted scope") {
		t.Fatalf("out-of-scope read allowed: %+v", check)
	}
}

func TestPidScopeEnforced(t *testing.T) {
	m := EmptyManager()
	m.Grant("local-agent", Capability{Action: "process.inspect", Scope: []string{"1000-2000"}})
	if !m.Check("local-agent", "process.inspect", "1500", time.Now()).Allowed {
		t.Error("pid in range denied")
	}
	for _, pid := range []string{"1", "99999", "abc"} {
		if m.Check("local-agent", "process.inspect", pid, time.Now()).Allowed {
			t.Errorf("pid %q allowed", pid)
		}
	}
}

func TestRevokeIsStickyAndRegrantClears(t *testing.T) {
	m := EmptyManager()
	m.Grant("local-agent", Capability{Action: "process.list"})
	if !m.Revoke("local-agent", "process.list") {
		t.Fatal("revoke reported nothing removed")
	}
	if check := m.Check("local-agent", "process.list", "", time.Now()); check.Allowed || !m.IsRevoked("local-agent", "process.list") {
		t.Fatalf("revoked capability still allowed: %+v", check)
	}
	m.Grant("local-agent", Capability{Action: "process.list"})
	if m.IsRevoked("local-agent", "process.list") {
		t.Fatal("regrant did not clear revocation")
	}
	if !m.Check("local-agent", "process.list", "", time.Now()).Allowed {
		t.Fatal("regranted capability denied")
	}
}

func TestRevokeAll(t *testing.T) {
	m := EmptyManager()
	m.Grant("local-agent", Capability{Action: "process.list"})
	m.Grant("local-agent", Capability{Action: "system.cpu"})
	if got := m.RevokeAll("local-agent"); got != 2 {
		t.Fatalf("RevokeAll = %d, want 2", got)
	}
	if m.Check("local-agent", "system.cpu", "", time.Now()).Allowed {
		t.Fatal("capability survived RevokeAll")
	}
}

func TestExpiredCapabilityIsDenied(t *testing.T) {
	past := time.Now().Add(-time.Second)
	m := EmptyManager()
	m.Grant("local-agent", Capability{Action: "process.list", ExpiresAt: &past})
	check := m.Check("local-agent", "process.list", "", time.Now())
	if check.Allowed || !check.Expired {
		t.Fatalf("expired capability allowed: %+v", check)
	}
}

func TestRegrantReplacesScope(t *testing.T) {
	m := EmptyManager()
	m.Grant("local-agent", Capability{Action: "filesystem.read", Scope: []string{"/home/*"}})
	m.Grant("local-agent", Capability{Action: "filesystem.read", Scope: []string{"/home/user/Downloads/*"}})
	if m.Check("local-agent", "filesystem.read", "/home/other/x", time.Now()).Allowed {
		t.Fatal("old scope survived regrant")
	}
	if !m.Check("local-agent", "filesystem.read", "/home/user/Downloads/x", time.Now()).Allowed {
		t.Fatal("new scope not applied")
	}
}

func TestDefaultGrantsAreReadOnlyVisibility(t *testing.T) {
	m := NewManager()
	for _, action := range []string{"filesystem.read", "filesystem.stat", "filesystem.list", "process.inspect"} {
		if m.Has("local-agent", action) {
			t.Errorf("default grant includes %s", action)
		}
	}
	for _, action := range []string{"system.cpu", "system.memory", "system.status", "process.list", "network.connections"} {
		if !m.Has("local-agent", action) {
			t.Errorf("default grant missing %s", action)
		}
	}
}
