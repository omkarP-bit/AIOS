// Package filesafety owns the non-negotiable filesystem rules for cleanup.
//
// The operator policy document lists protected paths, but the Go hard floor is
// authoritative: editing or deleting entries in data.json can never make a
// protected path eligible. Every rule is applied after realpath resolution, so
// symlinks cannot turn a harmless-looking path into a protected one.
package filesafety

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"aios/internal/config"
	"aios/internal/protocol"
)

// Floor is the hard-coded protected-path floor. It is deliberately duplicated
// in aios/policies/data.json for transparency; policy may add paths but never
// remove these.
var Floor = []string{
	"~/.ssh", "~/.gnupg", "~/.config", "~/.aios",
	"**/.git", "/etc", "/boot", "/usr", "/var", "/root", "/proc", "/sys",
}

// Target is the verified identity of one eligible file.
type Target struct {
	Realpath string
	Size     int64
	Mtime    int64
	Inode    uint64
	Device   uint64
	Owner    uint32
}

// Rules is an immutable set of resolved protected prefixes.
type Rules struct {
	prefixes  []string
	gitShield bool
}

// NewRules expands the supplied patterns against home. A pattern of "**/.git"
// protects a directory with that name at any depth.
func NewRules(home string, patterns []string) (Rules, error) {
	if home == "" {
		var err error
		home, err = os.UserHomeDir()
		if err != nil {
			return Rules{}, err
		}
	}
	r := Rules{prefixes: []string{}}
	seen := map[string]bool{}
	all := append(append([]string{}, Floor...), patterns...)
	for _, pattern := range all {
		prefix, git, err := expandPattern(pattern, home)
		if err != nil {
			return Rules{}, err
		}
		if git {
			r.gitShield = true
			continue
		}
		if !seen[prefix] {
			seen[prefix] = true
			r.prefixes = append(r.prefixes, prefix)
		}
	}
	return r, nil
}

// Load reads the protected-path list from the policy directory and unions it
// with the hard floor. Bad data fails closed.
func Load(policyDir string) (Rules, error) {
	raw, err := os.ReadFile(filepath.Join(policyDir, "data.json"))
	if err != nil {
		return Rules{}, fmt.Errorf("read policy data: %w", err)
	}
	var doc struct {
		AIOS struct {
			ProtectedPaths []string `json:"protected_paths"`
		} `json:"aios"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return Rules{}, fmt.Errorf("parse policy data: %w", err)
	}
	return NewRules("", doc.AIOS.ProtectedPaths)
}

// Default loads the installed policy document. If it is unreadable, the hard
// floor alone still applies; this keeps older installations fail-closed rather
// than taking down the core for a transparency-only file.
func Default() Rules {
	rules, err := Load(config.DefaultPolicyDir())
	if err != nil {
		rules, _ = NewRules("", nil)
	}
	return rules
}

// Configured reports whether any rules are present.
func (r Rules) Configured() bool { return len(r.prefixes) > 0 || r.gitShield }

// Patterns returns a copy of the resolved prefixes, for audit and tests.
func (r Rules) Patterns() []string { return append([]string(nil), r.prefixes...) }

// IsProtected reports whether path, its realpath, or any parent matches a
// protected prefix or a shielded .git directory.
func (r Rules) IsProtected(path string) bool {
	if path == "" {
		return true
	}
	if r.gitShield && hasSegment(path, ".git") {
		return true
	}
	for _, candidate := range realpathCandidates(path) {
		if r.gitShield && hasSegment(candidate, ".git") {
			return true
		}
		clean := filepath.Clean(candidate)
		for _, prefix := range r.prefixes {
			if clean == prefix || strings.HasPrefix(clean, prefix+string(filepath.Separator)) {
				return true
			}
		}
	}
	return false
}

// ValidateTarget checks one proposed file against root. It resolves symlinks
// first, then rejects protected paths, the scope root itself, symlink escape,
// cross-device moves, foreign owners, non-regular files, and hard links. The
// returned identity is captured from the live filesystem at call time.
func (r Rules) ValidateTarget(path, root string, uid uint32) (Target, error) {
	for _, value := range []string{path, root} {
		if err := protocol.ValidAbsolutePath(value); err != nil {
			return Target{}, fmt.Errorf("invalid path %q: %w", value, err)
		}
	}
	cleanPath := filepath.Clean(path)
	cleanRoot := filepath.Clean(root)
	if r.IsProtected(path) || r.IsProtected(root) {
		return Target{}, errors.New("target or root is a protected path")
	}
	realPath, err := filepath.EvalSymlinks(cleanPath)
	if err != nil {
		return Target{}, fmt.Errorf("cannot resolve target: %w", err)
	}
	realRoot, err := filepath.EvalSymlinks(cleanRoot)
	if err != nil {
		return Target{}, fmt.Errorf("cannot resolve root: %w", err)
	}
	// A symlink anywhere in the path is refused, not followed. Requiring the
	// lexical and real paths to match catches parent-directory symlinks too.
	if realPath != cleanPath || realRoot != cleanRoot {
		return Target{}, errors.New("symlink escape is not allowed")
	}
	if r.IsProtected(realPath) || r.IsProtected(realRoot) {
		return Target{}, errors.New("resolved target is a protected path")
	}
	if realPath == realRoot {
		return Target{}, errors.New("scope root is not an eligible target")
	}
	if realPath != realRoot && !strings.HasPrefix(realPath, realRoot+string(filepath.Separator)) {
		return Target{}, errors.New("target is outside the approved root")
	}
	rootInfo, err := os.Stat(realRoot)
	if err != nil {
		return Target{}, fmt.Errorf("cannot stat root: %w", err)
	}
	if !rootInfo.IsDir() {
		return Target{}, errors.New("root is not a directory")
	}
	info, err := os.Lstat(realPath)
	if err != nil {
		return Target{}, fmt.Errorf("cannot stat target: %w", err)
	}
	if !info.Mode().IsRegular() {
		return Target{}, errors.New("target is not a regular file")
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return Target{}, errors.New("target identity is unavailable")
	}
	if st.Uid != uid {
		return Target{}, errors.New("target belongs to another user")
	}
	rootStat, ok := rootInfo.Sys().(*syscall.Stat_t)
	if !ok || st.Dev != rootStat.Dev {
		return Target{}, errors.New("target crosses a device boundary")
	}
	if st.Nlink > 1 {
		return Target{}, errors.New("target has multiple hard links")
	}
	return Target{
		Realpath: realPath, Size: info.Size(), Mtime: info.ModTime().UnixNano(),
		Inode: st.Ino, Device: st.Dev, Owner: st.Uid,
	}, nil
}

// ValidatePlan checks every planned path. Directories are not eligible at all,
// so a non-empty directory can never be staged without all of its children
// being individual, identity-bound entries in the plan.
func (r Rules) ValidatePlan(paths []string, root string, uid uint32) ([]Target, error) {
	if len(paths) == 0 {
		return nil, errors.New("plan has no filesystem targets")
	}
	out := make([]Target, 0, len(paths))
	for _, path := range paths {
		target, err := r.ValidateTarget(path, root, uid)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		out = append(out, target)
	}
	return out, nil
}

func expandPattern(pattern, home string) (string, bool, error) {
	value := strings.TrimSpace(pattern)
	if value == "" {
		return "", false, errors.New("empty protected path")
	}
	if strings.ContainsRune(value, 0) {
		return "", false, errors.New("protected path contains NUL")
	}
	for _, r := range value {
		if r < 0x20 || r == 0x7f {
			return "", false, errors.New("protected path contains a control character")
		}
	}
	if value == "**/.git" {
		return "", true, nil
	}
	if strings.HasPrefix(value, "~/") {
		value = filepath.Join(home, value[2:])
	} else if value == "~" {
		value = home
	}
	if !filepath.IsAbs(value) {
		return "", false, fmt.Errorf("protected path must be absolute: %q", pattern)
	}
	for _, segment := range strings.Split(value, string(filepath.Separator)) {
		if segment == ".." {
			return "", false, fmt.Errorf("protected path contains traversal: %q", pattern)
		}
	}
	return filepath.Clean(value), false, nil
}

func realpathCandidates(path string) []string {
	out := []string{filepath.Clean(path)}
	if real, err := filepath.EvalSymlinks(path); err == nil {
		out = append(out, real)
	}
	return out
}

func hasSegment(path, want string) bool {
	for _, segment := range strings.Split(filepath.Clean(path), string(filepath.Separator)) {
		if strings.EqualFold(segment, want) {
			return true
		}
	}
	return false
}
