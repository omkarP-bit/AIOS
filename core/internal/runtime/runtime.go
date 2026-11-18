// Package runtime wires the components together. The CLI and the HTTP API use
// the same constructor so their behaviour cannot drift.
package runtime

import (
	"crypto/rand"
	"time"

	"aios/internal/actions"
	"aios/internal/capability"
	"aios/internal/config"
	"aios/internal/engine"
	"aios/internal/gateway"
	"aios/internal/ledger"
	"aios/internal/netctl"
	"aios/internal/plan"
	"aios/internal/policy"
)

// PlanTTL is how long a core-built plan may wait for approval.
const PlanTTL = 10 * time.Minute

// Runtime is one wired AIOS core.
type Runtime struct {
	Settings          config.Settings
	Gateway           *gateway.Gateway
	Executor          actions.Executor
	Capabilities      *capability.Manager
	Policy            policy.Engine
	Ledger            *ledger.Ledger
	Engine            *engine.Engine
	Plans             *plan.Registry
	Cleanups          *plan.CleanupRegistry
	Cleanup           *engine.CleanupService
	ApprovalAuthority *plan.Authority
	Network           *netctl.Manager
}

// New builds the read-only gateway, the mutation dispatcher, policy, the plan
// registry, and the audit sink.
func New(settings config.Settings) (*Runtime, error) {
	gw := gateway.New(settings.ProcRoot, settings.SysRoot, settings.QuarantineDir)

	// NetworkManager is optional: without the system bus the read-only
	// network views still work and network.prefer fails closed with a
	// backend_unavailable denial instead of taking down the whole core.
	var controller actions.NetworkController
	networkManager, err := netctl.Open()
	if err == nil {
		controller = networkManager
	} else {
		networkManager = nil
	}

	executor, err := actions.NewDispatcher(settings.QuarantineDir, settings.ProcRoot, controller)
	if err != nil {
		return nil, err
	}
	audit, err := ledger.New(settings.LedgerPath)
	if err != nil {
		return nil, err
	}
	policyDir := settings.PolicyDir
	if policyDir == "" {
		policyDir = config.DefaultPolicyDir()
	}
	local, err := policy.NewLocal(policyDir)
	if err != nil {
		return nil, err
	}
	p := policy.NewStricter(local, policy.NewRego(policyDir, settings.OPABinary, settings.OPATimeout))
	rt := &Runtime{
		Settings: settings, Gateway: gw, Executor: executor,
		Capabilities: capability.NewManager(), Policy: p, Ledger: audit,
		Plans: plan.NewRegistry(PlanTTL), Network: networkManager,
	}
	rt.Engine = engine.New(gw, executor, rt.Capabilities, p, audit)
	authority, err := rt.Authority()
	if err != nil {
		return nil, err
	}
	rt.ApprovalAuthority = authority
	rt.Cleanups = plan.NewCleanupRegistry(PlanTTL)
	rt.Cleanup = engine.NewCleanupService(rt.Engine, rt.Cleanups, authority)
	return rt, nil
}

// WithCapabilities replaces the grant table, used by the operator CLI to add
// the exact-path grants a cleanup command needs.
func (r *Runtime) WithCapabilities(manager *capability.Manager) *Runtime {
	r.Capabilities = manager
	r.Engine.Capabilities = manager
	return r
}

// Authority returns the approval authority. An empty configured secret means
// an ephemeral key: tokens cannot survive a restart, which is the documented
// behaviour and the safer default.
func (r *Runtime) Authority() (*plan.Authority, error) {
	secret := []byte(r.Settings.ApprovalSecret)
	if len(secret) == 0 {
		secret = make([]byte, 32)
		if _, err := rand.Read(secret); err != nil {
			return nil, err
		}
	}
	return plan.NewAuthority(secret, r.Settings.ApprovalTTL)
}
