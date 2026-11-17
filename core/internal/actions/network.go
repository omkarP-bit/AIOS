package actions

import (
	"errors"
	"time"

	"aios/internal/model"
	"aios/internal/netctl"
	"aios/internal/plan"
	"aios/internal/protocol"
)

// NetworkController is the narrow NetworkManager surface the executor needs.
// The concrete implementation lives in internal/netctl and never runs a
// command.
type NetworkController interface {
	Resolve(identifier string) (netctl.Connection, error)
	Activate(conn netctl.Connection, timeout time.Duration) (netctl.Activation, error)
}

// NetworkExecutor applies an approved network.prefer step.
type NetworkExecutor struct {
	Controller NetworkController
}

// Execute re-resolves the approved connection by UUID, verifies its identity,
// then asks NetworkManager to activate it.
func (e *NetworkExecutor) Execute(req *protocol.Request, p plan.Plan, grant plan.Grant) (model.StepResult, error) {
	if grant.PlanID != p.PlanID || grant.PlanHash != p.PlanHash {
		return model.StepResult{}, refuse("approval_invalid", "approval does not match the plan")
	}
	if !time.Now().Before(grant.ExpiresAt.Time) {
		return model.StepResult{}, refuse("approval_expired", "approval has expired")
	}
	params, ok := req.Typed.(*protocol.NetworkPreferParams)
	if !ok {
		return model.StepResult{}, refuse("executor_refused", "invalid network.prefer params")
	}
	if e.Controller == nil {
		return model.StepResult{}, refuse("network_backend_unavailable",
			"NetworkManager D-Bus backend is not available; run the core on the host")
	}
	step, err := p.StepByID(params.StepID)
	if err != nil {
		return model.StepResult{}, refuse("scope_mismatch", "%s", err.Error())
	}
	if step.Action != "network.prefer" {
		return model.StepResult{}, refuse("scope_mismatch", "step is not a network.prefer step")
	}
	if step.Target != params.Connection {
		return model.StepResult{}, refuse("scope_mismatch", "request connection does not match the approved step")
	}
	current, err := e.Controller.Resolve(params.Connection)
	if err != nil {
		return model.StepResult{}, refuse("target_missing", "cannot resolve connection: %v", err)
	}
	if current.UUID != params.Connection {
		return model.StepResult{}, refuse("target_changed", "connection id no longer resolves to the approved UUID")
	}
	if current.UUID != paramString(step.Params, "connection_uuid") ||
		current.Interface != paramString(step.Params, "interface") ||
		current.Type != paramString(step.Params, "type") {
		return model.StepResult{}, refuse("target_changed", "connection changed since the plan was approved")
	}
	activation, err := e.Controller.Activate(current, 8*time.Second)
	if err != nil {
		if errors.Is(err, netctl.ErrNotAuthorized) {
			return model.StepResult{}, refuse("not_permitted",
				"NetworkManager refused the activation; polkit may require an interactive approval")
		}
		return model.StepResult{}, refuse("executor_refused", "NetworkManager activation failed: %v", err)
	}
	status := "activated"
	detail := "NetworkManager reports the connection is active"
	if !activation.Activated {
		status = "activation_pending"
		detail = "NetworkManager accepted the request but has not reached the activated state yet"
	}
	if activation.Already {
		status = "already_active"
		detail = "the connection was already active; no change was made"
	}
	return model.StepResult{
		Action: "network.prefer", Target: current.UUID, Status: status,
		Detail: &detail,
		Data: map[string]any{
			"connection_uuid": current.UUID,
			"connection_id":   current.ID,
			"interface":       current.Interface,
			"ssid":            current.SSID,
			"state":           activation.State,
			"state_text":      activation.StateText,
			"already_active":  activation.Already,
		},
	}, nil
}
