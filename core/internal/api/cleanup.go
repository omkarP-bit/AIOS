package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"aios/internal/catalog"
	"aios/internal/engine"
	"aios/internal/plan"
	"aios/internal/policy"
)

// cleanupCriteriaRequest is the operator's selection rule. It contains no file
// names, contents, or free-text intent that could become a target.
type cleanupCriteriaRequest struct {
	Root         string   `json:"root"`
	MinAgeDays   int      `json:"min_age_days"`
	MinSizeBytes int64    `json:"min_size_bytes"`
	Extensions   []string `json:"extensions"`
	MaxResults   int      `json:"max_results"`
	AgentID      string   `json:"agent_id"`
	SessionID    string   `json:"session_id"`
}

func decodeCleanupCriteria(w http.ResponseWriter, r *http.Request) (cleanupCriteriaRequest, bool) {
	var payload cleanupCriteriaRequest
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&payload); err != nil {
		badRequest(w, errors.New("invalid request: "+err.Error()))
		return payload, false
	}
	if payload.MaxResults == 0 {
		payload.MaxResults = 500
	}
	if payload.AgentID == "" {
		payload.AgentID = "local-agent"
	}
	if payload.SessionID == "" {
		payload.SessionID = "cleanup"
	}
	if err := plan.ValidateCriteria(payload.criteria()); err != nil {
		badRequest(w, err)
		return payload, false
	}
	return payload, true
}

func (c cleanupCriteriaRequest) criteria() plan.Criteria {
	return plan.Criteria{
		Root: c.Root, MinAgeDays: c.MinAgeDays, MinSizeBytes: c.MinSizeBytes,
		Extensions: c.Extensions, MaxResults: c.MaxResults,
	}
}

// filesystemFind is the read-only deterministic scan. The origin and grant are
// set by the service, never by this request body.
func (s *Server) filesystemFind(w http.ResponseWriter, r *http.Request) {
	if s.rt.Cleanup == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "service_unavailable"})
		return
	}
	payload, ok := decodeCleanupCriteria(w, r)
	if !ok {
		return
	}
	verdict, scan, err := s.rt.Cleanup.Find(payload.criteria(), payload.AgentID, payload.SessionID)
	if err != nil {
		badRequest(w, err)
		return
	}
	body := map[string]any{"action": "filesystem.find", "verdict": verdict, "scan": scan}
	if verdict.Decision == policy.Deny {
		s.setReasonHeader(w, verdict)
		writeJSON(w, s.denialStatus(verdict), body)
		return
	}
	writeJSON(w, http.StatusOK, body)
}

// proposeCleanup builds an engine-owned plan from the scan. Callers cannot
// supply a path list; the plan body is derived entirely from scan results.
func (s *Server) proposeCleanup(w http.ResponseWriter, r *http.Request) {
	if s.rt.Cleanup == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "service_unavailable"})
		return
	}
	payload, ok := decodeCleanupCriteria(w, r)
	if !ok {
		return
	}
	p, verdict, err := s.rt.Cleanup.Propose(payload.criteria(), payload.AgentID, payload.SessionID)
	if err != nil {
		badRequest(w, err)
		return
	}
	body := map[string]any{
		"plan": p, "plan_id": p.PlanID, "plan_hash": p.PlanHash,
		"status": p.Status, "verdict": verdict, "requires_approval": true,
	}
	if verdict.Decision == policy.Deny {
		s.setReasonHeader(w, verdict)
		writeJSON(w, http.StatusForbidden, body)
		return
	}
	writeJSON(w, http.StatusOK, body)
}

func (s *Server) listCleanupPlans(w http.ResponseWriter, r *http.Request) {
	if s.rt.Cleanups == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "service_unavailable"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"plans": s.rt.Cleanups.List(time.Now())})
}

func (s *Server) getCleanupPlan(w http.ResponseWriter, r *http.Request) {
	if s.rt.Cleanups == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "service_unavailable"})
		return
	}
	p, err := s.rt.Cleanups.Get(r.PathValue("id"), time.Now())
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "plan_unavailable", "detail": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"plan": p})
}

type cleanupApproveRequest struct {
	PlanHash string `json:"plan_hash"`
	Operator string `json:"operator"`
}

func (s *Server) approveCleanup(w http.ResponseWriter, r *http.Request) {
	if s.rt.Cleanup == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "service_unavailable"})
		return
	}
	var payload cleanupApproveRequest
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&payload); err != nil {
		badRequest(w, errors.New("invalid request: "+err.Error()))
		return
	}
	if payload.PlanHash == "" {
		badRequest(w, errors.New("plan_hash is required"))
		return
	}
	if payload.Operator == "" {
		payload.Operator = strings.TrimSpace(r.Header.Get("X-AIOS-Operator"))
	}
	if payload.Operator == "" {
		payload.Operator = "operator-http"
	}
	p, err := s.rt.Cleanup.Approve(r.PathValue("id"), payload.PlanHash, payload.Operator)
	if err != nil {
		writeJSON(w, http.StatusConflict, map[string]any{"error": "approval_refused", "detail": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"plan": p, "plan_id": p.PlanID, "plan_hash": p.PlanHash,
		"status": p.Status, "approved_by": payload.Operator,
	})
}

func (s *Server) trashCleanup(w http.ResponseWriter, r *http.Request) {
	if s.rt.Cleanup == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "service_unavailable"})
		return
	}
	verdict, p, err := s.rt.Cleanup.Trash(r.PathValue("id"))
	if err != nil {
		writeJSON(w, http.StatusConflict, map[string]any{"error": "plan_unavailable", "detail": err.Error()})
		return
	}
	body := map[string]any{"verdict": verdict, "plan": p, "plan_id": p.PlanID, "plan_hash": p.PlanHash}
	if verdict.Decision == policy.Deny {
		s.setReasonHeader(w, verdict)
		writeJSON(w, http.StatusForbidden, body)
		return
	}
	writeJSON(w, http.StatusOK, body)
}

func (s *Server) restoreAction(w http.ResponseWriter, r *http.Request) {
	if s.rt.Cleanup == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "service_unavailable"})
		return
	}
	verdicts, err := s.rt.Cleanup.RestoreAction(r.PathValue("action_id"))
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "action_unavailable", "detail": err.Error()})
		return
	}
	body := map[string]any{"action_id": r.PathValue("action_id"), "verdicts": verdicts}
	for _, verdict := range verdicts {
		if verdict.Decision == policy.Deny {
			s.setReasonHeader(w, verdict)
			writeJSON(w, http.StatusForbidden, body)
			return
		}
	}
	writeJSON(w, http.StatusOK, body)
}

type capabilityGrantRequest struct {
	AgentID   string   `json:"agent_id"`
	Action    string   `json:"action"`
	Scope     []string `json:"scope"`
	GrantedBy string   `json:"granted_by"`
	Reason    string   `json:"reason"`
	TTL       string   `json:"ttl"`
}

func (s *Server) grantCapability(w http.ResponseWriter, r *http.Request) {
	var payload capabilityGrantRequest
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&payload); err != nil {
		badRequest(w, errors.New("invalid request: "+err.Error()))
		return
	}
	if payload.GrantedBy == "" {
		payload.GrantedBy = "operator-http"
	}
	ttl := 10 * time.Minute
	if payload.TTL != "" {
		parsed, err := time.ParseDuration(payload.TTL)
		if err != nil || parsed <= 0 || parsed > time.Hour {
			badRequest(w, errors.New("ttl must be a positive duration of at most one hour"))
			return
		}
		ttl = parsed
	}
	expires := time.Now().Add(ttl)
	granted, err := s.rt.Capabilities.GrantScoped(payload.AgentID, payload.Action,
		payload.Scope, &expires, payload.GrantedBy, payload.Reason)
	if err != nil {
		writeJSON(w, http.StatusForbidden, map[string]any{"error": "grant_refused", "detail": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"capability": granted})
}

type capabilityRevokeRequest struct {
	AgentID string `json:"agent_id"`
	Action  string `json:"action"`
}

func (s *Server) revokeCapability(w http.ResponseWriter, r *http.Request) {
	var payload capabilityRevokeRequest
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&payload); err != nil {
		badRequest(w, errors.New("invalid request: "+err.Error()))
		return
	}
	if payload.AgentID == "" || payload.Action == "" {
		badRequest(w, errors.New("agent_id and action are required"))
		return
	}
	if catalog.Forbidden[payload.Action] {
		badRequest(w, fmt.Errorf("action %q cannot be granted or revoked here", payload.Action))
		return
	}
	removed := s.rt.Capabilities.Revoke(payload.AgentID, payload.Action)
	writeJSON(w, http.StatusOK, map[string]any{
		"agent_id": payload.AgentID, "action": payload.Action, "revoked": removed,
	})
}

func (s *Server) setReasonHeader(w http.ResponseWriter, verdict engine.Verdict) {
	reason := string(verdict.Decision)
	if verdict.DenialReason != nil {
		reason = string(*verdict.DenialReason)
	}
	w.Header().Set("X-AIOS-Reason", reason)
}

// denialStatus distinguishes "not allowed" (403) from "service down" (503).
func (s *Server) denialStatus(verdict engine.Verdict) int {
	if verdict.DenialReason != nil {
		switch *verdict.DenialReason {
		case engine.PolicyUnavailable, engine.AuditUnavailable, engine.BackendUnavailable:
			return http.StatusServiceUnavailable
		}
	}
	return http.StatusForbidden
}
