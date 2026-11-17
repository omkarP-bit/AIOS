// Package catalog describes every action the system knows about.
//
// One descriptor per action. This is the Go source of truth; the Rego data
// document and the Python protocol must agree with it, and tests enforce
// that. The catalog says what an action *is*. Rego decides whether a
// particular proposal may run.
package catalog

// Effect classes. The order is also the order of increasing blast radius.
type Effect string

const (
	EffectObserve     Effect = "OBSERVE"
	EffectStage       Effect = "STAGE"
	EffectReversible  Effect = "REVERSIBLE"
	EffectDestructive Effect = "DESTRUCTIVE"
	EffectForbidden   Effect = "FORBIDDEN"
)

// ApprovalClass says what a human must do before the action may run.
type ApprovalClass string

const (
	ApprovalNone    ApprovalClass = "none"
	ApprovalConfirm ApprovalClass = "confirm"
	ApprovalPlan    ApprovalClass = "plan"
)

// Risk classes, ordered.
type Risk string

const (
	RiskLow      Risk = "LOW"
	RiskMedium   Risk = "MEDIUM"
	RiskHigh     Risk = "HIGH"
	RiskCritical Risk = "CRITICAL"
)

// CatalogVersion participates in plan hashing. Bump it when the meaning of an
// existing descriptor changes, not when an action is added.
const CatalogVersion = "2026-11-13"

// Limits are the per-plan ceilings enforced by the core and by Rego.
type Limits struct {
	MaxItems int   `json:"max_items"`
	MaxBytes int64 `json:"max_bytes"`
}

// Descriptor is one action record.
type Descriptor struct {
	ID         string
	Version    int
	Effect     Effect
	Risk       Risk
	Scope      string // none, path, pid, uid
	Approval   ApprovalClass
	ReadOnly   bool
	PathAction bool
	Inverse    string
	Limits     Limits
	OWASP      []string
}

// Catalog is the closed action set.
var Catalog = map[string]Descriptor{
	"system.cpu": {
		ID: "system.cpu", Version: 1, Effect: EffectObserve, Risk: RiskLow,
		Scope: "none", Approval: ApprovalNone, ReadOnly: true,
		OWASP: []string{"OWASP-A01:2021", "OWASP-ASVS4-V4"},
	},
	"system.memory": {
		ID: "system.memory", Version: 1, Effect: EffectObserve, Risk: RiskLow,
		Scope: "none", Approval: ApprovalNone, ReadOnly: true,
		OWASP: []string{"OWASP-A01:2021"},
	},
	"system.hostname": {
		ID: "system.hostname", Version: 1, Effect: EffectObserve, Risk: RiskLow,
		Scope: "none", Approval: ApprovalNone, ReadOnly: true,
		OWASP: []string{"OWASP-A01:2021"},
	},
	"system.status": {
		ID: "system.status", Version: 1, Effect: EffectObserve, Risk: RiskLow,
		Scope: "none", Approval: ApprovalNone, ReadOnly: true,
		OWASP: []string{"OWASP-A01:2021"},
	},
	"system.uptime": {
		ID: "system.uptime", Version: 1, Effect: EffectObserve, Risk: RiskLow,
		Scope: "none", Approval: ApprovalNone, ReadOnly: true,
		OWASP: []string{"OWASP-A01:2021"},
	},
	"process.list": {
		ID: "process.list", Version: 1, Effect: EffectObserve, Risk: RiskLow,
		Scope: "none", Approval: ApprovalNone, ReadOnly: true,
		OWASP: []string{"OWASP-A01:2021", "OWASP-LLM01:2025"},
	},
	"process.inspect": {
		ID: "process.inspect", Version: 1, Effect: EffectObserve, Risk: RiskLow,
		Scope: "pid", Approval: ApprovalNone, ReadOnly: true,
		OWASP: []string{"OWASP-A01:2021", "OWASP-LLM01:2025"},
	},
	"process.diagnose": {
		ID: "process.diagnose", Version: 1, Effect: EffectObserve, Risk: RiskLow,
		Scope: "none", Approval: ApprovalNone, ReadOnly: true,
		OWASP: []string{"OWASP-A01:2021", "OWASP-LLM01:2025"},
	},
	"process.signal": {
		ID: "process.signal", Version: 1, Effect: EffectDestructive, Risk: RiskHigh,
		Scope: "pid", Approval: ApprovalPlan, ReadOnly: false,
		Limits: Limits{MaxItems: 1},
		OWASP: []string{
			"OWASP-LLM06:2025", "OWASP-A01:2021", "OWASP-ASVS4-V4",
		},
	},
	"network.connections": {
		ID: "network.connections", Version: 1, Effect: EffectObserve, Risk: RiskLow,
		Scope: "none", Approval: ApprovalNone, ReadOnly: true,
		OWASP: []string{"OWASP-A01:2021"},
	},
	"network.status": {
		ID: "network.status", Version: 1, Effect: EffectObserve, Risk: RiskLow,
		Scope: "none", Approval: ApprovalNone, ReadOnly: true,
		OWASP: []string{"OWASP-A01:2021"},
	},
	"network.prefer": {
		ID: "network.prefer", Version: 1, Effect: EffectReversible, Risk: RiskHigh,
		Scope: "connection", Approval: ApprovalPlan, ReadOnly: false,
		Inverse: "network.prefer",
		Limits:  Limits{MaxItems: 1},
		OWASP: []string{
			"OWASP-LLM06:2025", "OWASP-A01:2021", "OWASP-A08:2021",
		},
	},
	"filesystem.list": {
		ID: "filesystem.list", Version: 1, Effect: EffectObserve, Risk: RiskLow,
		Scope: "path", Approval: ApprovalNone, ReadOnly: true, PathAction: true,
		OWASP: []string{"OWASP-A01:2021", "OWASP-ASVS4-V12"},
	},
	"filesystem.stat": {
		ID: "filesystem.stat", Version: 1, Effect: EffectObserve, Risk: RiskLow,
		Scope: "path", Approval: ApprovalNone, ReadOnly: true, PathAction: true,
		OWASP: []string{"OWASP-A01:2021", "OWASP-ASVS4-V12"},
	},
	"filesystem.read": {
		ID: "filesystem.read", Version: 1, Effect: EffectObserve, Risk: RiskMedium,
		Scope: "path", Approval: ApprovalConfirm, ReadOnly: true, PathAction: true,
		OWASP: []string{"OWASP-LLM01:2025", "OWASP-LLM02:2025", "OWASP-ASVS4-V12"},
	},
	"filesystem.cleanup_scan": {
		ID: "filesystem.cleanup_scan", Version: 1, Effect: EffectObserve, Risk: RiskLow,
		Scope: "path", Approval: ApprovalNone, ReadOnly: true, PathAction: true,
		Limits: Limits{MaxItems: 5000, MaxBytes: 0},
		OWASP:  []string{"OWASP-LLM06:2025", "OWASP-A01:2021", "OWASP-ASVS4-V12"},
	},
	"filesystem.quarantine": {
		ID: "filesystem.quarantine", Version: 1, Effect: EffectStage, Risk: RiskHigh,
		Scope: "path", Approval: ApprovalPlan, ReadOnly: false, PathAction: true,
		Inverse: "filesystem.restore",
		Limits:  Limits{MaxItems: 500, MaxBytes: 10_737_418_240},
		OWASP: []string{
			"OWASP-LLM06:2025", "OWASP-A01:2021", "OWASP-A08:2021",
			"OWASP-ASVS4-V4", "OWASP-ASVS4-V12",
		},
	},
	"filesystem.restore": {
		ID: "filesystem.restore", Version: 1, Effect: EffectReversible, Risk: RiskHigh,
		Scope: "path", Approval: ApprovalPlan, ReadOnly: false, PathAction: true,
		Inverse: "filesystem.quarantine",
		Limits:  Limits{MaxItems: 500, MaxBytes: 10_737_418_240},
		OWASP: []string{
			"OWASP-LLM06:2025", "OWASP-A01:2021", "OWASP-A08:2021",
			"OWASP-ASVS4-V4", "OWASP-ASVS4-V12",
		},
	},
}

// Forbidden is permanently outside every AI path.
var Forbidden = map[string]bool{
	"process.terminate": true, "process.kill": true,
	"filesystem.write": true, "filesystem.delete": true, "filesystem.rm": true,
	"filesystem.mkdir": true, "filesystem.chmod": true, "filesystem.chown": true,
	"filesystem.move": true, "filesystem.purge": true,
	"network.block": true, "network.open": true, "network.listen": true,
	"firewall.modify": true, "package.install": true, "package.remove": true,
	"service.start": true, "service.stop": true, "kernel.modify": true,
	"sysctl.write": true, "system.shutdown": true, "system.reboot": true,
	"shell.exec": true, "command.run": true, "exec": true,
}

// ExecutorActions are served by the mutation executor, not the gateway.
var ExecutorActions = map[string]bool{
	"filesystem.quarantine": true,
	"filesystem.restore":    true,
	"process.signal":        true,
	"network.prefer":        true,
}

// PlanActions always require a plan and an operator approval.
var PlanActions = map[string]bool{
	"filesystem.quarantine": true,
	"filesystem.restore":    true,
	"process.signal":        true,
	"network.prefer":        true,
}

// Lookup returns the descriptor for an action.
func Lookup(action string) (Descriptor, bool) {
	d, ok := Catalog[action]
	return d, ok
}

// EffectFor returns FORBIDDEN for an unknown action, never OBSERVE.
func EffectFor(action string) Effect {
	if d, ok := Catalog[action]; ok {
		return d.Effect
	}
	return EffectForbidden
}

// IsReadOnly reports whether the gateway may serve the action.
func IsReadOnly(action string) bool {
	d, ok := Catalog[action]
	return ok && d.ReadOnly
}

// RequiresPlan reports whether an approval token is mandatory.
func RequiresPlan(action string) bool {
	return PlanActions[action]
}

// RiskFor returns the risk class for an action. Unknown actions are CRITICAL,
// so a missing entry can never be treated as low risk.
func RiskFor(action string) Risk {
	if d, ok := Catalog[action]; ok {
		return d.Risk
	}
	return RiskCritical
}

// ScopeDimensionFor returns the scope dimension for an action.
func ScopeDimensionFor(action string) string {
	if d, ok := Catalog[action]; ok {
		return d.Scope
	}
	return "none"
}

// PathParam reports whether the action's params carry a path.
func PathParam(action string) bool {
	d, ok := Catalog[action]
	return ok && d.PathAction
}
