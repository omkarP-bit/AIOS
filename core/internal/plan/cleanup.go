// Package plan owns immutable, hash-bound plans. CleanupPlan is the
// filesystem-specific shape: it is built by the security engine from a
// deterministic scan, never from a model-supplied list of paths.
package plan

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"aios/internal/canonical"
	"aios/internal/model"
)

// CleanupStatus is the engine-owned lifecycle of a cleanup plan. Status is not
// part of the plan hash: it changes after approval, and the hash must remain
// the value the operator approved.
type CleanupStatus string

const (
	CleanupPendingApproval CleanupStatus = "PENDING_APPROVAL"
	CleanupApproved        CleanupStatus = "APPROVED"
	CleanupExpired         CleanupStatus = "EXPIRED"
	CleanupExecuted        CleanupStatus = "EXECUTED"
	CleanupRejected        CleanupStatus = "REJECTED"
)

var cleanupTransitions = map[CleanupStatus]map[CleanupStatus]bool{
	CleanupPendingApproval: {
		CleanupApproved: true, CleanupExpired: true, CleanupRejected: true,
	},
	CleanupApproved: {
		CleanupExecuted: true, CleanupExpired: true, CleanupRejected: true,
	},
	CleanupExpired:  {},
	CleanupExecuted: {},
	CleanupRejected: {},
}

// CanTransitionCleanup reports whether a plan status edge is legal.
func CanTransitionCleanup(from, to CleanupStatus) bool {
	return cleanupTransitions[from][to]
}

// AssertCleanupTransition returns an error instead of panicking on a bad edge.
func AssertCleanupTransition(from, to CleanupStatus) error {
	if !CanTransitionCleanup(from, to) {
		return fmt.Errorf("illegal cleanup plan transition: %s -> %s", from, to)
	}
	return nil
}

// Criteria is the complete, deterministic selection rule for a cleanup plan.
// It comes from the operator or the CLI; model prose is never parsed into it.
type Criteria struct {
	Root         string   `json:"root"`
	MinAgeDays   int      `json:"min_age_days"`
	MinSizeBytes int64    `json:"min_size_bytes"`
	Extensions   []string `json:"extensions,omitempty"`
	MaxResults   int      `json:"max_results"`
}

// Entry is one file selected by the scan. Every field is captured at scan time
// so execution can detect a swap before moving anything.
type Entry struct {
	Realpath string `json:"realpath"`
	Size     int64  `json:"size"`
	Mtime    int64  `json:"mtime"` // Unix nanoseconds
	Inode    uint64 `json:"inode"`
	Device   uint64 `json:"device"`
	Owner    uint32 `json:"owner"`
}

// CleanupPlan is the exact object an operator approves. No AI-visible shape
// exposes approval booleans or per-path authorization flags.
type CleanupPlan struct {
	PlanID     string          `json:"plan_id"`
	SessionID  string          `json:"session_id"`
	AgentID    string          `json:"agent_id"`
	CreatedAt  model.Timestamp `json:"created_at"`
	ExpiresAt  model.Timestamp `json:"expires_at"`
	Root       string          `json:"root"`
	Criteria   Criteria        `json:"criteria"`
	Entries    []Entry         `json:"entries"`
	FileCount  int             `json:"file_count"`
	TotalBytes int64           `json:"total_bytes"`
	PlanHash   string          `json:"plan_hash"`
	Status     CleanupStatus   `json:"status"`
}

// CleanupSummary is the only plan shape shown to the AI or rendered in chat.
// It deliberately has no approval or path-in-plan flags.
type CleanupSummary struct {
	PlanID     string          `json:"plan_id"`
	SessionID  string          `json:"session_id"`
	Root       string          `json:"root"`
	Criteria   Criteria        `json:"criteria"`
	FileCount  int             `json:"file_count"`
	TotalBytes int64           `json:"total_bytes"`
	ExpiresAt  model.Timestamp `json:"expires_at"`
	PlanHash   string          `json:"plan_hash"`
	Status     CleanupStatus   `json:"status"`
}

// Summary returns the safe, AI-visible projection of the plan.
func (p CleanupPlan) Summary() CleanupSummary {
	return CleanupSummary{
		PlanID: p.PlanID, SessionID: p.SessionID, Root: p.Root,
		Criteria: p.Criteria, FileCount: p.FileCount, TotalBytes: p.TotalBytes,
		ExpiresAt: p.ExpiresAt, PlanHash: p.PlanHash, Status: p.Status,
	}
}

// body returns the canonical hash input. Status and PlanHash are excluded:
// both are engine bookkeeping, not part of what the operator approved.
func (p CleanupPlan) body() map[string]any {
	entries := make([]map[string]any, 0, len(p.Entries))
	for _, e := range p.Entries {
		entries = append(entries, map[string]any{
			"realpath": e.Realpath, "size": e.Size, "mtime": e.Mtime,
			"inode": e.Inode, "device": e.Device, "owner": e.Owner,
		})
	}
	criteria := map[string]any{
		"root": p.Criteria.Root, "min_age_days": p.Criteria.MinAgeDays,
		"min_size_bytes": p.Criteria.MinSizeBytes,
		"max_results":    p.Criteria.MaxResults,
	}
	if len(p.Criteria.Extensions) > 0 {
		criteria["extensions"] = append([]string(nil), p.Criteria.Extensions...)
	}
	return map[string]any{
		"plan_id": p.PlanID, "session_id": p.SessionID, "agent_id": p.AgentID,
		"created_at": model.FormatTime(p.CreatedAt.Time),
		"expires_at": model.FormatTime(p.ExpiresAt.Time),
		"root":       p.Root, "criteria": criteria, "entries": entries,
		"file_count": p.FileCount, "total_bytes": p.TotalBytes,
	}
}

// ComputeCleanupHash returns the SHA-256 of the canonical plan body.
func ComputeCleanupHash(p CleanupPlan) (string, error) {
	raw, err := canonical.Marshal(p.body())
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

// NewCleanupPlan is the single constructor for a cleanup plan. It is called by
// the security engine after a deterministic scan and never with a list of
// paths supplied by the model. Invalid criteria fail closed.
func NewCleanupPlan(agentID, sessionID string, criteria Criteria, entries []Entry, ttl time.Duration, now time.Time) (CleanupPlan, error) {
	if criteria.Root == "" || !filepath.IsAbs(criteria.Root) {
		return CleanupPlan{}, errors.New("root must be an absolute path")
	}
	if strings.ContainsRune(criteria.Root, 0) {
		return CleanupPlan{}, errors.New("root contains a null byte")
	}
	if criteria.MinAgeDays < 0 {
		return CleanupPlan{}, errors.New("min_age_days must be non-negative")
	}
	if criteria.MinSizeBytes < 0 {
		return CleanupPlan{}, errors.New("min_size_bytes must be non-negative")
	}
	if criteria.MaxResults < 1 {
		return CleanupPlan{}, errors.New("max_results must be positive")
	}
	if ttl <= 0 {
		ttl = 10 * time.Minute
	}
	copyEntries := append([]Entry(nil), entries...)
	sort.Slice(copyEntries, func(i, j int) bool {
		return copyEntries[i].Realpath < copyEntries[j].Realpath
	})
	var total int64
	for _, e := range copyEntries {
		if e.Realpath == "" || !filepath.IsAbs(e.Realpath) {
			return CleanupPlan{}, errors.New("entry realpath must be absolute")
		}
		if e.Size < 0 {
			return CleanupPlan{}, errors.New("entry size must be non-negative")
		}
		total += e.Size
	}
	created := now.UTC().Truncate(time.Microsecond)
	p := CleanupPlan{
		PlanID: NewID(), AgentID: agentID, SessionID: sessionID,
		CreatedAt: model.Timestamp{Time: created},
		ExpiresAt: model.Timestamp{Time: created.Add(ttl)},
		Root:      filepath.Clean(criteria.Root), Criteria: criteria,
		Entries: copyEntries, FileCount: len(copyEntries), TotalBytes: total,
		Status: CleanupPendingApproval,
	}
	hash, err := ComputeCleanupHash(p)
	if err != nil {
		return CleanupPlan{}, err
	}
	p.PlanHash = hash
	return p, nil
}
