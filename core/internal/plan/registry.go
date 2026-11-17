package plan

import (
	"errors"
	"sync"
	"time"
)

// Registry holds core-built plans between proposal and approval. Only a plan
// the core built itself can be applied; a caller cannot supply a plan body and
// ask the core to trust its hash.
type Registry struct {
	mu    sync.Mutex
	ttl   time.Duration
	plans map[string]entry
}

type entry struct {
	plan      Plan
	createdAt time.Time
	used      bool
}

// NewRegistry builds a plan registry. A zero ttl falls back to ten minutes.
func NewRegistry(ttl time.Duration) *Registry {
	if ttl <= 0 {
		ttl = 10 * time.Minute
	}
	return &Registry{ttl: ttl, plans: map[string]entry{}}
}

// Put stores a freshly built plan, replacing any previous entry with the same
// id. Ids are random, so a collision is not expected.
func (r *Registry) Put(p Plan, now time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.prune(now)
	r.plans[p.PlanID] = entry{plan: p, createdAt: now}
}

// Take returns the stored plan and marks it used. A plan can be applied once.
// The supplied hash must match the stored plan exactly.
func (r *Registry) Take(planID, planHash string, now time.Time) (Plan, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.prune(now)
	stored, ok := r.plans[planID]
	if !ok {
		return Plan{}, errors.New("plan is unknown or has expired")
	}
	if stored.used {
		return Plan{}, errors.New("plan was already applied")
	}
	if stored.plan.PlanHash != planHash {
		return Plan{}, errors.New("plan hash does not match the stored plan")
	}
	if now.Sub(stored.createdAt) > r.ttl {
		delete(r.plans, planID)
		return Plan{}, errors.New("plan has expired")
	}
	stored.used = true
	r.plans[planID] = stored
	return stored.plan, nil
}

func (r *Registry) prune(now time.Time) {
	for id, stored := range r.plans {
		if now.Sub(stored.createdAt) > r.ttl {
			delete(r.plans, id)
		}
	}
}
