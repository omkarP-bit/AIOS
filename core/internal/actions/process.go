package actions

import (
	"os"
	"strconv"
	"syscall"
	"time"

	"aios/internal/model"
	"aios/internal/observe"
	"aios/internal/plan"
	"aios/internal/protocol"
)

// Signals a plan may request. The set is closed: there is no signal number or
// arbitrary kill in the protocol.
var Signals = map[string]syscall.Signal{
	"TERM": syscall.SIGTERM,
	"KILL": syscall.SIGKILL,
	"HUP":  syscall.SIGHUP,
	"INT":  syscall.SIGINT,
	"QUIT": syscall.SIGQUIT,
	"STOP": syscall.SIGSTOP,
	"CONT": syscall.SIGCONT,
}

// ProcessExecutor is the only component that may signal a process.
type ProcessExecutor struct {
	ProcRoot string
	EUID     int
}

// NewProcessExecutor binds the executor to the host procfs and the user it is
// allowed to act as. Signals are same-user only; a root core does not get to
// signal arbitrary host processes through this path.
func NewProcessExecutor(procRoot string) *ProcessExecutor {
	if procRoot == "" {
		procRoot = "/proc"
	}
	return &ProcessExecutor{ProcRoot: procRoot, EUID: os.Geteuid()}
}

// Execute runs one approved process.signal step after re-checking identity.
func (e *ProcessExecutor) Execute(req *protocol.Request, p plan.Plan, grant plan.Grant) (model.StepResult, error) {
	if grant.PlanID != p.PlanID || grant.PlanHash != p.PlanHash {
		return model.StepResult{}, refuse("approval_invalid", "approval does not match the plan")
	}
	if !time.Now().Before(grant.ExpiresAt.Time) {
		return model.StepResult{}, refuse("approval_expired", "approval has expired")
	}
	params, ok := req.Typed.(*protocol.ProcessSignalParams)
	if !ok {
		return model.StepResult{}, refuse("executor_refused", "invalid process.signal params")
	}
	step, err := p.StepByID(params.StepID)
	if err != nil {
		return model.StepResult{}, refuse("scope_mismatch", "%s", err.Error())
	}
	if step.Action != "process.signal" {
		return model.StepResult{}, refuse("scope_mismatch", "step is not a process.signal step")
	}
	if step.Target != strconv.Itoa(params.PID) {
		return model.StepResult{}, refuse("scope_mismatch", "request pid does not match the approved step")
	}
	if signalName(step.Params) != params.Signal {
		return model.StepResult{}, refuse("scope_mismatch", "request signal does not match the approved step")
	}
	signal, known := Signals[params.Signal]
	if !known {
		return model.StepResult{}, refuse("executor_refused", "unknown signal %q", params.Signal)
	}
	if params.PID <= 1 {
		return model.StepResult{}, refuse("executor_refused", "pid 1 is never signalled")
	}
	if params.PID == os.Getpid() {
		return model.StepResult{}, refuse("executor_refused", "the core will not signal itself")
	}

	current, err := observe.ReadProcessIdentity(e.ProcRoot, params.PID)
	if err != nil {
		return model.StepResult{}, refuse("target_missing", "cannot read pid %d: %v", params.PID, err)
	}
	if err := e.verifyIdentity(step, current); err != nil {
		return model.StepResult{}, err
	}
	if current.State == "Z" {
		return model.StepResult{}, refuse("zombie_not_killable",
			"pid %d is a zombie; it is already dead and cannot be killed. Its parent must reap it.", params.PID)
	}
	if current.UID != e.EUID {
		return model.StepResult{}, refuse("not_permitted",
			"pid %d is owned by uid %d, not the core's uid %d", params.PID, current.UID, e.EUID)
	}
	if err := syscall.Kill(params.PID, signal); err != nil {
		return model.StepResult{}, refuse("not_permitted", "signal %s to pid %d failed: %v", params.Signal, params.PID, err)
	}
	after, _ := observe.ReadProcessIdentity(e.ProcRoot, params.PID)
	stateAfter := "unknown"
	if after.PID != 0 {
		stateAfter = after.State
	} else {
		stateAfter = "gone"
	}
	detail := "signal delivered; a process may take time to exit"
	return model.StepResult{
		Action: "process.signal", Target: step.Target, PID: params.PID,
		Signal: params.Signal, Status: "signal_sent", Detail: &detail,
		Data: map[string]any{
			"name":           current.Name,
			"uid":            current.UID,
			"start_time_utc": current.StartTimeUTC,
			"state_before":   current.State,
			"state_after":    stateAfter,
			"signal":         params.Signal,
		},
	}, nil
}

func (e *ProcessExecutor) verifyIdentity(step plan.Step, current observe.ProcessIdentity) error {
	wantStart := paramInt(step.Params, "start_ticks")
	wantUID := paramInt(step.Params, "uid")
	wantName := paramString(step.Params, "name")
	if int64(current.StartTicks) != wantStart || current.UID != int(wantUID) || current.Name != wantName {
		return refuse("target_changed",
			"pid %d changed since the plan was approved (start time, owner, or name)", current.PID)
	}
	return nil
}

func signalName(params map[string]any) string {
	if params == nil {
		return ""
	}
	value, _ := params["signal"].(string)
	return value
}

func paramInt(params map[string]any, key string) int64 {
	if params == nil {
		return 0
	}
	switch value := params[key].(type) {
	case int:
		return int64(value)
	case int64:
		return value
	case float64:
		return int64(value)
	default:
		return 0
	}
}

func paramString(params map[string]any, key string) string {
	if params == nil {
		return ""
	}
	value, _ := params[key].(string)
	return value
}
