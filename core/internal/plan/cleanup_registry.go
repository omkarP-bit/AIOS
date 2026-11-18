package plan

import (
	"errors"
	"sync"
	"time"
)

// CleanupRegistry holds core-built cleanup plans between proposal, approval,
// and execution. Callers can only read copies: status and the signed approval
// token are engine-owned state, never request fields.
type CleanupRegistry struct {
	mu    sync.Mutex
	ttl   time.Duration
	plans map[string]cleanupEntry
}

type cleanupEntry struct {
	plan      CleanupPlan
	createdAt time.Time
	approval  *Token
}

// NewCleanupRegistry builds a registry with the given plan lifetime.
func NewCleanupRegistry(ttl time.Duration) *CleanupRegistry {
	if ttl <= 0 {
		ttl = 10 * time.Minute
	}
	return &CleanupRegistry{ttl: ttl, plans: map[string]cleanupEntry{}}
}

// Put stores a freshly built plan.
func (r *CleanupRegistry) Put(p CleanupPlan, now time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.prune(now)
	r.plans[p.PlanID] = cleanupEntry{plan: p, createdAt: now}
}

// Get returns a copy of a live plan.
func (r *CleanupRegistry) Get(planID string, now time.Time) (CleanupPlan, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.prune(now)
	stored, ok := r.plans[planID]
	if !ok {
		return CleanupPlan{}, errors.New("cleanup plan is unknown or has expired")
	}
	return copyCleanup(stored.plan), nil
}

// Approval returns a copy of the plan and its signed token. A plan that has not
// been approved has no token.
func (r *CleanupRegistry) Approval(planID string, now time.Time) (CleanupPlan, *Token, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.prune(now)
	stored, ok := r.plans[planID]
	if !ok {
		return CleanupPlan{}, nil, errors.New("cleanup plan is unknown or has expired")
	}
	if stored.approval == nil {
		return copyCleanup(stored.plan), nil, errors.New("cleanup plan has not been approved")
	}
	token := *stored.approval
	return copyCleanup(stored.plan), &token, nil
}

// List returns the AI-safe summaries of all live plans.
func (r *CleanupRegistry) List(now time.Time) []CleanupSummary {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.prune(now)
	out := make([]CleanupSummary, 0, len(r.plans))
	for _, stored := range r.plans {
		out = append(out, stored.plan.Summary())
	}
	return out
}

// SetApproval stores the signed token for an exact plan body. The supplied hash
// must match the stored plan, and the plan must still be awaiting approval.
func (r *CleanupRegistry) SetApproval(planID, planHash string, token Token, now time.Time) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.prune(now)
	stored, ok := r.plans[planID]
	if !ok {
		return errors.New("cleanup plan is unknown or has expired")
	}
	if stored.plan.PlanHash != planHash {
		return errors.New("plan hash does not match the stored plan")
	}
	if stored.plan.Status != CleanupPendingApproval {
		return errors.New("cleanup plan is not awaiting approval")
	}
	if !now.Before(stored.plan.ExpiresAt.Time) {
		return errors.New("cleanup plan has expired")
	}
	stored.approval = &token
	r.plans[planID] = stored
	return nil
}

// SetStatus moves an exact plan to a later lifecycle state.
func (r *CleanupRegistry) SetStatus(planID, planHash string, status CleanupStatus, now time.Time) (CleanupPlan, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.prune(now)
	stored, ok := r.plans[planID]
	if !ok {
		return CleanupPlan{}, errors.New("cleanup plan is unknown or has expired")
	}
	if stored.plan.PlanHash != planHash {
		return CleanupPlan{}, errors.New("plan hash does not match the stored plan")
	}
	if err := AssertCleanupTransition(stored.plan.Status, status); err != nil {
		return CleanupPlan{}, err
	}
	stored.plan.Status = status
	r.plans[planID] = stored
	return copyCleanup(stored.plan), nil
}

func (r *CleanupRegistry) prune(now time.Time) {
	for id, stored := range r.plans {
		if !now.Before(stored.plan.ExpiresAt.Time) {
			delete(r.plans, id)
		}
	}
}

func copyCleanup(p CleanupPlan) CleanupPlan {
	copy := p
	copy.Criteria.Extensions = append([]string(nil), p.Criteria.Extensions...)
	copy.Entries = append([]Entry(nil), p.Entries...)
	return copy
}
