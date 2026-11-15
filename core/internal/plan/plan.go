// Package plan builds immutable cleanup plans and the hash that binds an
// approval to them.
//
// The hash is computed here, never accepted from a planner. Every field that
// changes what will be touched is inside it, including the catalog version.
package plan

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"aios/internal/canonical"
	"aios/internal/catalog"
	"aios/internal/model"
)

// Limits bound one plan.
type Limits struct {
	MaxItems int   `json:"max_items"`
	MaxBytes int64 `json:"max_bytes"`
}

// Step is one quarantine operation.
type Step struct {
	StepID      string `json:"step_id"`
	Action      string `json:"action"`
	CandidateID string `json:"candidate_id"`
	Path        string `json:"path"`
	Dev         uint64 `json:"dev"`
	Ino         uint64 `json:"ino"`
	SizeBytes   int64  `json:"size_bytes"`
	MtimeNS     int64  `json:"mtime_ns"`
	Mode        uint32 `json:"mode"`
	UID         uint32 `json:"uid"`
}

// RollbackStep is the inverse operation for a step.
type RollbackStep struct {
	StepID      string `json:"step_id"`
	Action      string `json:"action"`
	CandidateID string `json:"candidate_id"`
	Path        string `json:"path"`
}

// Plan is the immutable, hash-bound unit an operator approves.
type Plan struct {
	PlanID         string          `json:"plan_id"`
	CatalogVersion string          `json:"catalog_version"`
	AgentID        string          `json:"agent_id"`
	SessionID      string          `json:"session_id"`
	Intent         *string         `json:"intent"`
	CreatedAt      model.Timestamp `json:"created_at"`
	Roots          []string        `json:"roots"`
	Limits         Limits          `json:"limits"`
	Steps          []Step          `json:"steps"`
	Rollback       []RollbackStep  `json:"rollback"`
	PlanHash       string          `json:"plan_hash"`
}

// NewID returns "plan-" plus 24 hex characters.
func NewID() string {
	buf := make([]byte, 12)
	if _, err := rand.Read(buf); err != nil {
		panic("crypto/rand unavailable: " + err.Error())
	}
	return "plan-" + hex.EncodeToString(buf)
}

// FromCandidates builds a plan from scanner output. Extra candidates beyond
// maxItems are dropped, never silently included.
func FromCandidates(candidates []model.Candidate, root, agentID, sessionID string, intent *string, maxItems int, maxBytes int64, now time.Time) Plan {
	if maxItems < 1 || maxItems > 5000 {
		maxItems = 500
	}
	chosen := candidates
	if len(chosen) > maxItems {
		chosen = chosen[:maxItems]
	}
	steps := make([]Step, 0, len(chosen))
	rollback := make([]RollbackStep, 0, len(chosen))
	for i, c := range chosen {
		stepID := fmt.Sprintf("step-%d", i+1)
		steps = append(steps, Step{
			StepID: stepID, Action: "filesystem.quarantine",
			CandidateID: c.CandidateID, Path: c.Path, Dev: c.Dev, Ino: c.Ino,
			SizeBytes: c.SizeBytes, MtimeNS: c.MtimeNS, Mode: c.Mode, UID: c.UID,
		})
		rollback = append(rollback, RollbackStep{
			StepID: stepID, Action: "filesystem.restore",
			CandidateID: c.CandidateID, Path: c.Path,
		})
	}
	p := Plan{
		PlanID: NewID(), CatalogVersion: catalog.CatalogVersion,
		AgentID: agentID, SessionID: sessionID, Intent: intent,
		CreatedAt: model.Timestamp{Time: now.UTC().Truncate(time.Microsecond)},
		Roots:     []string{root},
		Limits:    Limits{MaxItems: maxItems, MaxBytes: maxBytes},
		Steps:     steps, Rollback: rollback,
	}
	p.PlanHash = ComputeHash(p)
	return p
}

// body returns the canonical JSON body, excluding plan_hash.
func (p Plan) body() map[string]any {
	steps := make([]map[string]any, 0, len(p.Steps))
	for _, s := range p.Steps {
		steps = append(steps, map[string]any{
			"step_id": s.StepID, "action": s.Action, "candidate_id": s.CandidateID,
			"path": s.Path, "dev": s.Dev, "ino": s.Ino, "size_bytes": s.SizeBytes,
			"mtime_ns": s.MtimeNS, "mode": s.Mode, "uid": s.UID,
		})
	}
	rollback := make([]map[string]any, 0, len(p.Rollback))
	for _, r := range p.Rollback {
		rollback = append(rollback, map[string]any{
			"step_id": r.StepID, "action": r.Action,
			"candidate_id": r.CandidateID, "path": r.Path,
		})
	}
	roots := make([]string, len(p.Roots))
	copy(roots, p.Roots)
	var intent any
	if p.Intent != nil {
		intent = *p.Intent
	}
	return map[string]any{
		"plan_id":         p.PlanID,
		"catalog_version": p.CatalogVersion,
		"agent_id":        p.AgentID,
		"session_id":      p.SessionID,
		"intent":          intent,
		"created_at":      model.FormatTime(p.CreatedAt.Time),
		"roots":           roots,
		"limits":          map[string]any{"max_items": p.Limits.MaxItems, "max_bytes": p.Limits.MaxBytes},
		"steps":           steps,
		"rollback":        rollback,
	}
}

// ComputeHash returns the sha256 of the canonical body plus the catalog
// version, matching the Python reference byte for byte.
func ComputeHash(p Plan) string {
	body, err := canonical.Marshal(p.body())
	if err != nil {
		panic("plan body is not marshalable: " + err.Error())
	}
	version, err := canonical.Marshal(map[string]any{"catalog_version": p.CatalogVersion})
	if err != nil {
		panic("catalog version is not marshalable: " + err.Error())
	}
	sum := sha256.Sum256(append(body, version...))
	return "sha256:" + hex.EncodeToString(sum[:])
}

// TotalBytes sums the step sizes.
func (p Plan) TotalBytes() int64 {
	var total int64
	for _, s := range p.Steps {
		total += s.SizeBytes
	}
	return total
}

// Validate checks the invariants the executor relies on. It does not replace
// Rego; it stops an incoherent plan before policy is consulted.
func (p Plan) Validate() error {
	if p.PlanID == "" || len(p.Steps) == 0 {
		return errors.New("plan is empty")
	}
	if len(p.Steps) > p.Limits.MaxItems {
		return errors.New("plan exceeds max_items")
	}
	if p.TotalBytes() > p.Limits.MaxBytes {
		return errors.New("plan exceeds max_bytes")
	}
	if len(p.Roots) == 0 {
		return errors.New("plan has no approved roots")
	}
	for _, s := range p.Steps {
		if catalog.Forbidden[s.Action] {
			return fmt.Errorf("step %s uses forbidden action %s", s.StepID, s.Action)
		}
		if !catalog.RequiresPlan(s.Action) {
			return fmt.Errorf("step %s is not a plan action", s.StepID)
		}
		if s.Path == "" {
			return fmt.Errorf("step %s has no path", s.StepID)
		}
	}
	if p.PlanHash != ComputeHash(p) {
		return errors.New("plan hash does not match the plan body")
	}
	return nil
}

// PolicyDoc is the plan summary handed to Rego as read-only input.
func (p Plan) PolicyDoc() map[string]any {
	forbidden := false
	for _, s := range p.Steps {
		if catalog.Forbidden[s.Action] {
			forbidden = true
		}
	}
	return map[string]any{
		"id": p.PlanID, "hash": p.PlanHash, "steps": len(p.Steps),
		"forbidden_step": forbidden,
		"limits": map[string]any{
			"items_ok": len(p.Steps) <= p.Limits.MaxItems,
			"bytes_ok": p.TotalBytes() <= p.Limits.MaxBytes,
		},
	}
}

// StepFor finds the approved step for a candidate and checks the request path
// agrees with it. A request cannot redirect an approved step elsewhere.
func (p Plan) StepFor(candidateID, path string) (Step, error) {
	for _, s := range p.Steps {
		if s.CandidateID != candidateID {
			continue
		}
		if s.Path != path {
			return Step{}, errors.New("request path does not match the approved plan")
		}
		return s, nil
	}
	return Step{}, fmt.Errorf("%s is not part of this plan", candidateID)
}
