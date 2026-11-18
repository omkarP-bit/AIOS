// Package capability implements grants, scope matching, and the deny-by-
// default check.
//
// A capability is an exact action name, optionally narrowed by a scope. There
// is no implication: process.list never grants process.inspect, and a grant on
// a directory never authorises reading files inside it.
package capability

import (
	"errors"
	"fmt"
	"path"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"aios/internal/catalog"
	"aios/internal/protocol"
)

// Capability is one grant.
type Capability struct {
	Action    string     `json:"action"`
	Scope     []string   `json:"scope"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
	GrantedBy string     `json:"granted_by"`
	Reason    string     `json:"reason,omitempty"`
}

// Display renders the grant for audit rows.
func (c Capability) Display() string {
	if len(c.Scope) == 0 {
		return c.Action
	}
	return c.Action + ":" + strings.Join(c.Scope, ",")
}

// Expired reports whether the grant has lapsed at now.
func (c Capability) Expired(now time.Time) bool {
	return c.ExpiresAt != nil && !now.Before(*c.ExpiresAt)
}

// Check is the result of one capability lookup.
type Check struct {
	AgentID           string `json:"agent_id"`
	Action            string `json:"action"`
	Allowed           bool   `json:"allowed"`
	Reason            string `json:"reason"`
	MatchedCapability string `json:"matched_capability,omitempty"`
	Target            string `json:"target,omitempty"`
	Dimension         string `json:"dimension"`
	Risk              string `json:"risk"`
	Expired           bool   `json:"expired"`
}

// DefaultCapabilities is read-only system visibility, no filesystem paths.
func DefaultCapabilities() []Capability {
	return []Capability{
		{Action: "system.cpu", Reason: "system visibility", GrantedBy: "capability-manager"},
		{Action: "system.memory", Reason: "system visibility", GrantedBy: "capability-manager"},
		{Action: "system.hostname", Reason: "system visibility", GrantedBy: "capability-manager"},
		{Action: "system.status", Reason: "system visibility", GrantedBy: "capability-manager"},
		{Action: "system.uptime", Reason: "system visibility", GrantedBy: "capability-manager"},
		{Action: "process.list", Reason: "process visibility", GrantedBy: "capability-manager"},
		{Action: "process.diagnose", Reason: "process visibility", GrantedBy: "capability-manager"},
		{Action: "network.connections", Reason: "network visibility", GrantedBy: "capability-manager"},
		{Action: "network.status", Reason: "network visibility", GrantedBy: "capability-manager"},
		{Action: "filesystem.usage", Reason: "disk capacity visibility", GrantedBy: "capability-manager"},
	}
}

// ValidateScopePattern validates an operator grant pattern before it is
// installed. Wildcards must be scoped at least three segments deep: "/*" and
// "/home/*" are rejected, while "/home/alice/Downloads/*" is accepted.
// Relative paths, home expansion, NUL, and control characters are rejected.
func ValidateScopePattern(pattern string) error {
	if err := protocol.ValidAbsolutePath(pattern); err != nil {
		return err
	}
	if pattern == "/" {
		return errors.New("root scope is not allowed")
	}
	segments := splitSegments(pattern)
	if len(segments) == 0 {
		return errors.New("scope must not be empty")
	}
	if strings.ContainsAny(pattern, "*?[") {
		if len(segments) < 3 {
			return fmt.Errorf("root-level wildcards are not allowed: %q", pattern)
		}
		for _, segment := range segments[:2] {
			if strings.ContainsAny(segment, "*?[") {
				return fmt.Errorf("wildcard must be at least three segments deep: %q", pattern)
			}
		}
	}
	return nil
}

// Manager owns the in-process grant table.
type Manager struct {
	mu      sync.RWMutex
	grants  map[string][]Capability
	revoked map[string][]Capability
}

// NewManager builds a manager. With no explicit grants it installs the
// read-only defaults for local-agent, matching the Python reference.
func NewManager(defaults ...Capability) *Manager {
	m := &Manager{grants: map[string][]Capability{}, revoked: map[string][]Capability{}}
	if len(defaults) == 0 {
		defaults = DefaultCapabilities()
	}
	for _, cap := range defaults {
		m.Grant("local-agent", cap)
	}
	return m
}

// EmptyManager starts with no grants at all.
func EmptyManager() *Manager {
	return &Manager{grants: map[string][]Capability{}, revoked: map[string][]Capability{}}
}

// Grant installs a capability, replacing any previous scope for that action.
func (m *Manager) Grant(agentID string, cap Capability) Capability {
	if cap.GrantedBy == "" {
		cap.GrantedBy = "capability-manager"
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	bucket := m.grants[agentID]
	replaced := bucket[:0]
	for _, existing := range bucket {
		if !catalog.SameAction(existing.Action, cap.Action) {
			replaced = append(replaced, existing)
		}
	}
	m.grants[agentID] = append(replaced, cap)
	kept := m.revoked[agentID][:0]
	for _, existing := range m.revoked[agentID] {
		if !catalog.SameAction(existing.Action, cap.Action) {
			kept = append(kept, existing)
		}
	}
	m.revoked[agentID] = kept
	return cap
}

// GrantScoped is the operator-facing grant path. It validates the action and
// every scope pattern, attaches an expiry, and leaves an auditable reason.
func (m *Manager) GrantScoped(agentID, action string, patterns []string, expiresAt *time.Time, grantedBy, reason string) (Capability, error) {
	if agentID == "" {
		return Capability{}, errors.New("agent_id must not be empty")
	}
	if _, ok := catalog.Catalog[action]; !ok {
		return Capability{}, fmt.Errorf("unknown action %q", action)
	}
	if catalog.Forbidden[action] {
		return Capability{}, fmt.Errorf("action %q is forbidden", action)
	}
	dimension := catalog.ScopeDimensionFor(action)
	if dimension == "path" && len(patterns) == 0 {
		return Capability{}, errors.New("PATH actions require a non-empty scope")
	}
	scopes := append([]string(nil), patterns...)
	for _, pattern := range scopes {
		if err := ValidateScopePattern(pattern); err != nil {
			return Capability{}, err
		}
	}
	if expiresAt == nil || !expiresAt.After(time.Now()) {
		return Capability{}, errors.New("grant expiry must be in the future")
	}
	cap := Capability{
		Action: action, Scope: scopes, ExpiresAt: expiresAt,
		GrantedBy: grantedBy, Reason: reason,
	}
	return m.Grant(agentID, cap), nil
}

// Revoke removes a grant and records it as revoked.
func (m *Manager) Revoke(agentID, action string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	bucket := m.grants[agentID]
	removed := []Capability{}
	kept := []Capability{}
	for _, cap := range bucket {
		if catalog.SameAction(cap.Action, action) {
			removed = append(removed, cap)
		} else {
			kept = append(kept, cap)
		}
	}
	if len(removed) == 0 {
		return false
	}
	m.grants[agentID] = kept
	m.revoked[agentID] = append(m.revoked[agentID], removed...)
	return true
}

// RevokeAll removes every grant for an agent.
func (m *Manager) RevokeAll(agentID string) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	count := len(m.grants[agentID])
	m.revoked[agentID] = append(m.revoked[agentID], m.grants[agentID]...)
	m.grants[agentID] = nil
	return count
}

// CapabilitiesFor returns a copy of the agent's grants.
func (m *Manager) CapabilitiesFor(agentID string) []Capability {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return append([]Capability(nil), m.grants[agentID]...)
}

// Has reports whether the agent has a grant for the action.
func (m *Manager) Has(agentID, action string) bool {
	for _, cap := range m.CapabilitiesFor(agentID) {
		if catalog.SameAction(cap.Action, action) {
			return true
		}
	}
	return false
}

// IsRevoked reports whether the action was revoked.
func (m *Manager) IsRevoked(agentID, action string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, cap := range m.revoked[agentID] {
		if catalog.SameAction(cap.Action, action) {
			return true
		}
	}
	return false
}

// Check evaluates one action against an agent's grants.
func (m *Manager) Check(agentID, action, target string, now time.Time) Check {
	dimension := catalog.ScopeDimensionFor(action)
	risk := string(catalog.RiskFor(action))
	result := Check{
		AgentID: agentID, Action: action, Dimension: dimension,
		Risk: risk, Target: target,
	}

	if m.IsRevoked(agentID, action) {
		result.Reason = "capability was revoked for this agent"
		return result
	}

	candidates := []Capability{}
	for _, cap := range m.CapabilitiesFor(agentID) {
		if catalog.SameAction(cap.Action, action) {
			candidates = append(candidates, cap)
		}
	}
	if len(candidates) == 0 {
		result.Reason = "no capability grant for this action (deny by default)"
		return result
	}

	if (dimension == "pid" || dimension == "uid") && target != "" {
		if _, err := strconv.Atoi(target); err != nil {
			result.Reason = "target " + strconv.Quote(target) + " is not a valid " + dimension
			return result
		}
	}

	// A PATH action without a resolved target is never authorized. The old
	// `target == ""` shortcut let a scoped grant cover an unspecified target,
	// which could turn into any path later in the pipeline.
	if dimension == "path" && target == "" {
		result.Reason = "path action requires a resolved target"
		return result
	}
	for _, cap := range candidates {
		if cap.Expired(now) {
			continue
		}
		if dimension == "none" {
			result.Allowed = true
			result.Reason = "capability granted"
			result.MatchedCapability = cap.Display()
			return result
		}
		if dimension == "path" && len(cap.Scope) == 0 {
			continue
		}
		switch dimension {
		case "path":
			if PathInScope(target, cap.Scope) {
				result.Allowed = true
			}
		case "pid":
			pid, _ := strconv.Atoi(target)
			if PIDInScope(pid, cap.Scope) {
				result.Allowed = true
			}
		case "uid":
			uid, _ := strconv.Atoi(target)
			if PIDInScope(uid, cap.Scope) {
				result.Allowed = true
			}
		case "connection":
			if ConnectionInScope(target, cap.Scope) {
				result.Allowed = true
			}
		}
		if result.Allowed {
			result.Reason = "target is within capability scope"
			result.MatchedCapability = cap.Display()
			return result
		}
	}

	allExpired := true
	for _, cap := range candidates {
		if !cap.Expired(now) {
			allExpired = false
			break
		}
	}
	if allExpired {
		result.Reason = "capability has expired"
		result.Expired = true
		return result
	}
	result.Reason = "target " + strconv.Quote(target) + " is outside every granted scope for " + action
	return result
}

// PathInScope matches a normalised path against scope patterns.
//
// Scope semantics (tested below):
//   - "/a/b/*" matches every descendant of /a/b at any depth, but not /a/b
//     itself. It is recursive.
//   - "/a/*/c" is single-segment per wildcard: only /a/<one>/c matches.
//   - "/a/**/c" is recursive: /a/c and /a/x/y/c both match.
//   - A pattern without a wildcard matches one exact path.
//   - An empty pattern list never matches.
func PathInScope(target string, patterns []string) bool {
	if len(patterns) == 0 {
		return false
	}
	candidate := protocol.NormalisePath(target)
	for _, pattern := range patterns {
		if matchPath(candidate, pattern) {
			return true
		}
	}
	return false
}

func matchPath(candidate, pattern string) bool {
	if strings.HasSuffix(pattern, "/*") {
		prefix := protocol.NormalisePath(strings.TrimSuffix(pattern, "/*"))
		if candidate == prefix {
			return false
		}
		return strings.HasPrefix(candidate, prefix+"/")
	}
	normalised := pattern
	if strings.Contains(pattern, "/") {
		normalised = protocol.NormalisePath(strings.TrimSuffix(pattern, "/"))
	}
	if strings.ContainsAny(normalised, "*?[") {
		return matchSegments(splitSegments(candidate), splitSegments(normalised))
	}
	return candidate == normalised
}

func splitSegments(value string) []string {
	parts := []string{}
	for _, part := range strings.Split(strings.Trim(value, "/"), "/") {
		if part != "" {
			parts = append(parts, part)
		}
	}
	return parts
}

func matchSegments(candidate, pattern []string) bool {
	if len(pattern) == 0 {
		return len(candidate) == 0
	}
	if pattern[0] == "**" {
		if matchSegments(candidate, pattern[1:]) {
			return true
		}
		return len(candidate) > 0 && matchSegments(candidate[1:], pattern)
	}
	if len(candidate) == 0 {
		return false
	}
	matched, err := path.Match(pattern[0], candidate[0])
	if err != nil || !matched {
		return false
	}
	return matchSegments(candidate[1:], pattern[1:])
}

var (
	numericRe = regexp.MustCompile(`^\d+$`)
	rangeRe   = regexp.MustCompile(`^(\d+)-(\d+)$`)
)

// PIDInScope supports a number, a range, a comma list, globs, and '*'.
func PIDInScope(pid int, patterns []string) bool {
	value := strconv.Itoa(pid)
	for _, raw := range patterns {
		pattern := strings.TrimSpace(raw)
		if pattern == "*" {
			return true
		}
		if numericRe.MatchString(pattern) {
			if pattern == value {
				return true
			}
			continue
		}
		if match := rangeRe.FindStringSubmatch(pattern); match != nil {
			low, _ := strconv.Atoi(match[1])
			high, _ := strconv.Atoi(match[2])
			if low <= pid && pid <= high {
				return true
			}
			continue
		}
		if strings.Contains(pattern, ",") {
			for _, part := range strings.Split(pattern, ",") {
				if strings.TrimSpace(part) == value {
					return true
				}
			}
			continue
		}
		if matched, err := path.Match(pattern, value); err == nil && matched {
			return true
		}
	}
	return false
}

// UIDInScope is PIDInScope for numeric uids.
func UIDInScope(uid int, patterns []string) bool {
	return PIDInScope(uid, patterns)
}

// ConnectionInScope matches a NetworkManager connection UUID or id exactly.
// There is no wildcard: a grant names one connection.
func ConnectionInScope(target string, patterns []string) bool {
	for _, pattern := range patterns {
		if strings.TrimSpace(pattern) == target {
			return true
		}
	}
	return false
}
