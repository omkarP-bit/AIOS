// Package runtime wires the components together. The CLI and the HTTP API use
// the same constructor so their behaviour cannot drift.
package runtime

import (
	"crypto/rand"

	"aios/internal/actions"
	"aios/internal/capability"
	"aios/internal/config"
	"aios/internal/engine"
	"aios/internal/gateway"
	"aios/internal/ledger"
	"aios/internal/plan"
	"aios/internal/policy"
)

// Runtime is one wired AIOS core.
type Runtime struct {
	Settings     config.Settings
	Gateway      *gateway.Gateway
	Executor     *actions.QuarantineExecutor
	Capabilities *capability.Manager
	Policy       policy.Engine
	Ledger       *ledger.Ledger
	Engine       *engine.Engine
}

// New builds the read-only gateway, the separate mutation executor, policy,
// and the audit sink.
func New(settings config.Settings) (*Runtime, error) {
	gw := gateway.New(settings.ProcRoot, settings.SysRoot, settings.QuarantineDir)
	executor, err := actions.NewQuarantineExecutor(settings.QuarantineDir)
	if err != nil {
		return nil, err
	}
	audit, err := ledger.New(settings.LedgerPath)
	if err != nil {
		return nil, err
	}
	p := policy.NewRego(settings.PolicyDir, settings.OPABinary, settings.OPATimeout)
	rt := &Runtime{
		Settings: settings, Gateway: gw, Executor: executor,
		Capabilities: capability.NewManager(), Policy: p, Ledger: audit,
	}
	rt.Engine = engine.New(gw, executor, rt.Capabilities, p, audit)
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
