package engine

import (
	"errors"
	"fmt"
	"time"

	"aios/internal/capability"
	"aios/internal/model"
	"aios/internal/plan"
	"aios/internal/policy"
	"aios/internal/protocol"
)

// CleanupService is the only path from operator criteria to a reversible file
// move. It builds plans from deterministic scans, keeps approval state in the
// core, and routes execution through the same engine every other action uses.
type CleanupService struct {
	Engine    *Engine
	Cleanups  *plan.CleanupRegistry
	Authority *plan.Authority
}

// NewCleanupService wires the cleanup service to an engine.
func NewCleanupService(engine *Engine, cleanups *plan.CleanupRegistry, authority *plan.Authority) *CleanupService {
	return &CleanupService{Engine: engine, Cleanups: cleanups, Authority: authority}
}

// Find runs a deterministic scan through the normal read pipeline. Origin and
// capability are set here, server-side; a caller cannot claim a trusted origin
// or widen the grant.
func (s *CleanupService) Find(criteria plan.Criteria, agentID, sessionID string) (Verdict, *model.ScanResult, error) {
	if err := plan.ValidateCriteria(criteria); err != nil {
		return Verdict{}, nil, err
	}
	if s.Engine == nil {
		return Verdict{}, nil, errors.New("engine is unavailable")
	}
	params := map[string]any{
		"root":           criteria.Root,
		"min_age_days":   criteria.MinAgeDays,
		"min_size_bytes": criteria.MinSizeBytes,
		"extensions":     criteria.Extensions,
		"max_results":    criteria.MaxResults,
	}
	req, err := protocol.NewRequest("filesystem.find", params,
		protocol.WithOrigin(protocol.OriginUser),
		protocol.WithAgent(agentID), protocol.WithSession(sessionID))
	if err != nil {
		return Verdict{}, nil, err
	}
	manager := capability.EmptyManager()
	for _, grant := range s.Engine.Capabilities.CapabilitiesFor(agentID) {
		manager.Grant(agentID, grant)
	}
	manager.Grant(agentID, capability.Capability{
		Action: "filesystem.find", Scope: []string{criteria.Root},
		GrantedBy: "operator-find", Reason: "operator cleanup scan",
	})
	findEngine := New(s.Engine.Gateway, s.Engine.Executor, manager, s.Engine.Policy, s.Engine.Ledger)
	verdict := findEngine.Process(req, nil, nil)
	if verdict.Decision != policy.Allow || verdict.Observation == nil {
		return verdict, nil, nil
	}
	scan, ok := verdict.Observation.Data.(model.ScanResult)
	if !ok {
		return Verdict{}, nil, errors.New("scan observation has an invalid shape")
	}
	return verdict, &scan, nil
}

// Propose builds a cleanup plan from a scan. The target list is produced by the
// scanner and captured with full file identity; no caller-supplied path enters
// the plan body.
func (s *CleanupService) Propose(criteria plan.Criteria, agentID, sessionID string) (plan.CleanupPlan, Verdict, error) {
	verdict, scan, err := s.Find(criteria, agentID, sessionID)
	if err != nil || scan == nil {
		return plan.CleanupPlan{}, verdict, err
	}
	entries := make([]plan.Entry, 0, len(scan.Candidates))
	for _, candidate := range scan.Candidates {
		entries = append(entries, plan.Entry{
			Realpath: candidate.Path, Size: candidate.SizeBytes, Mtime: candidate.MtimeNS,
			Inode: candidate.Ino, Device: candidate.Dev, Owner: candidate.UID, Mode: candidate.Mode,
		})
	}
	p, err := plan.NewCleanupPlan(agentID, sessionID, criteria, entries, runtimePlanTTL(), time.Now())
	if err != nil {
		return plan.CleanupPlan{}, verdict, err
	}
	s.Cleanups.Put(p, time.Now())
	return p, verdict, nil
}

// Approve binds the operator's approval to the exact stored plan. Capabilities
// are granted only here, only for the paths in that plan, and only after the
// hash, status, and expiry checks pass.
func (s *CleanupService) Approve(planID, planHash, operator string) (plan.CleanupPlan, error) {
	if operator == "" {
		return plan.CleanupPlan{}, errors.New("operator identity is required")
	}
	if s.Authority == nil {
		return plan.CleanupPlan{}, errors.New("approval authority is unavailable")
	}
	p, err := s.Cleanups.Get(planID, time.Now())
	if err != nil {
		return plan.CleanupPlan{}, err
	}
	if p.PlanHash != planHash {
		return plan.CleanupPlan{}, errors.New("plan hash does not match the stored plan")
	}
	if p.Status != plan.CleanupPendingApproval {
		return plan.CleanupPlan{}, errors.New("cleanup plan is not awaiting approval")
	}
	if !time.Now().Before(p.ExpiresAt.Time) {
		return plan.CleanupPlan{}, errors.New("cleanup plan has expired")
	}
	generic := p.ToGeneric()
	if err := generic.Validate(); err != nil {
		return plan.CleanupPlan{}, fmt.Errorf("derived plan is invalid: %w", err)
	}
	token, err := s.Authority.Mint(generic, operator, 0)
	if err != nil {
		return plan.CleanupPlan{}, err
	}
	if err := s.Cleanups.SetApproval(planID, planHash, token, time.Now()); err != nil {
		return plan.CleanupPlan{}, err
	}
	approved, err := s.Cleanups.SetStatus(planID, planHash, plan.CleanupApproved, time.Now())
	if err != nil {
		return plan.CleanupPlan{}, err
	}
	// One capability per action, with the complete exact-path scope from the
	// plan. Grant replaces the previous scope for the same action, so granting
	// per entry would leave only the last path authorised.
	paths := make([]string, 0, len(p.Entries))
	for _, entry := range p.Entries {
		paths = append(paths, entry.Realpath)
	}
	s.Engine.Capabilities.Grant(p.AgentID, capability.Capability{
		Action: "filesystem.trash", Scope: paths,
		GrantedBy: "operator-approval:" + operator, Reason: "approved plan " + planID,
	})
	s.Engine.Capabilities.Grant(p.AgentID, capability.Capability{
		Action: "filesystem.restore", Scope: paths,
		GrantedBy: "operator-approval:" + operator, Reason: "approved plan " + planID,
	})
	return approved, nil
}

// Trash executes an approved plan. The signed token is consumed once, the
// request carries only a plan id, and the plan is marked EXECUTED only after
// the engine reports a successful execution.
func (s *CleanupService) Trash(planID string) (Verdict, plan.CleanupPlan, error) {
	if s.Authority == nil {
		return Verdict{}, plan.CleanupPlan{}, errors.New("approval authority is unavailable")
	}
	p, token, err := s.Cleanups.Approval(planID, time.Now())
	if err != nil {
		return Verdict{}, p, err
	}
	if p.Status != plan.CleanupApproved {
		return Verdict{}, p, errors.New("cleanup plan is not approved")
	}
	generic := p.ToGeneric()
	if err := generic.Validate(); err != nil {
		return Verdict{}, p, err
	}
	grant, err := s.Authority.Verify(*token, generic, true, time.Now())
	if err != nil {
		return Verdict{}, p, err
	}
	req, err := protocol.NewRequest("filesystem.trash", map[string]any{"plan_id": planID},
		protocol.WithOrigin(protocol.OriginUser),
		protocol.WithAgent(p.AgentID), protocol.WithSession(p.SessionID))
	if err != nil {
		return Verdict{}, p, err
	}
	verdict := s.Engine.Process(req, &generic, &grant)
	if verdict.Decision == policy.Allow && verdict.Executed {
		if _, err := s.Cleanups.SetStatus(planID, p.PlanHash, plan.CleanupExecuted, time.Now()); err != nil {
			return verdict, p, err
		}
	}
	return verdict, p, nil
}

// RestoreAction restores every entry moved by one trash action. It recovers
// the plan from the durable AUTHORIZED row, never from caller-supplied paths.
func (s *CleanupService) RestoreAction(actionID string) ([]Verdict, error) {
	if s.Engine == nil || s.Engine.Ledger == nil {
		return nil, errors.New("audit trail is unavailable")
	}
	planID := ""
	for _, entry := range s.Engine.Ledger.ByAction(actionID) {
		if entry.State == string(protocol.StateAuthorized) && entry.PlanID != nil {
			planID = *entry.PlanID
		}
	}
	if planID == "" {
		return nil, errors.New("action has no authorized cleanup plan")
	}
	p, err := s.Cleanups.Get(planID, time.Now())
	if err != nil {
		return nil, err
	}
	generic := p.ToGeneric()
	if err := generic.Validate(); err != nil {
		return nil, err
	}
	verdicts := make([]Verdict, 0, len(generic.Steps))
	for _, step := range generic.Steps {
		token, err := s.Authority.Mint(generic, "operator-restore", 0)
		if err != nil {
			return nil, err
		}
		grant, err := s.Authority.Verify(token, generic, true, time.Now())
		if err != nil {
			return nil, err
		}
		req, err := protocol.NewRequest("filesystem.restore", map[string]any{
			"path": step.Path, "plan_id": generic.PlanID, "candidate_id": step.CandidateID,
		}, protocol.WithOrigin(protocol.OriginUser),
			protocol.WithAgent(p.AgentID), protocol.WithSession(p.SessionID))
		if err != nil {
			return nil, err
		}
		verdicts = append(verdicts, s.Engine.Process(req, &generic, &grant))
	}
	return verdicts, nil
}

// runtimePlanTTL is defined here so cleanup plans use the same lifetime as
// generic core-built plans without importing the runtime package (which would
// create a cycle).
func runtimePlanTTL() time.Duration { return 10 * time.Minute }
