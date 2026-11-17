package actions

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"aios/internal/model"
	"aios/internal/plan"
	"aios/internal/protocol"
)

// ExecutorError carries a stable reason for the ledger.
type ExecutorError struct {
	Message string
	Reason  string
}

func (e ExecutorError) Error() string { return e.Message }

func refuse(reason, format string, args ...any) ExecutorError {
	return ExecutorError{Message: fmt.Sprintf(format, args...), Reason: reason}
}

// Executor runs one approved step for the action it serves.
type Executor interface {
	Execute(req *protocol.Request, p plan.Plan, grant plan.Grant) (model.StepResult, error)
}

// Dispatcher routes each approved step to its action family executor. It is
// the only mutation entry point the engine sees.
type Dispatcher struct {
	Quarantine *QuarantineExecutor
	Process    *ProcessExecutor
	Network    *NetworkExecutor
}

// NewDispatcher builds the mutation executors for this host.
func NewDispatcher(quarantineDir, procRoot string, network NetworkController) (*Dispatcher, error) {
	quarantine, err := NewQuarantineExecutor(quarantineDir)
	if err != nil {
		return nil, err
	}
	return &Dispatcher{
		Quarantine: quarantine,
		Process:    NewProcessExecutor(procRoot),
		Network:    &NetworkExecutor{Controller: network},
	}, nil
}

// Execute dispatches by action name.
func (d *Dispatcher) Execute(req *protocol.Request, p plan.Plan, grant plan.Grant) (model.StepResult, error) {
	switch req.ActionName() {
	case "filesystem.quarantine", "filesystem.restore":
		if d.Quarantine == nil {
			return model.StepResult{}, refuse("executor_unavailable", "quarantine executor is not configured")
		}
		return d.Quarantine.Execute(req, p, grant)
	case "process.signal":
		if d.Process == nil {
			return model.StepResult{}, refuse("executor_unavailable", "process executor is not configured")
		}
		return d.Process.Execute(req, p, grant)
	case "network.prefer":
		if d.Network == nil {
			return model.StepResult{}, refuse("executor_unavailable", "network executor is not configured")
		}
		return d.Network.Execute(req, p, grant)
	default:
		return model.StepResult{}, refuse("executor_refused", "%s is not a mutation action", req.ActionName())
	}
}

// QuarantineExecutor is the only component that may move a candidate.
type QuarantineExecutor struct {
	Dir string
}

// NewQuarantineExecutor resolves the quarantine root once.
func NewQuarantineExecutor(dir string) (*QuarantineExecutor, error) {
	expanded := os.ExpandEnv(dir)
	if strings.HasPrefix(expanded, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, err
		}
		expanded = filepath.Join(home, expanded[2:])
	}
	resolved, err := filepath.Abs(expanded)
	if err != nil {
		return nil, err
	}
	return &QuarantineExecutor{Dir: resolved}, nil
}

// Execute runs one approved step. It re-checks identity immediately before the
// rename and never recurses.
func (e *QuarantineExecutor) Execute(req *protocol.Request, p plan.Plan, grant plan.Grant) (model.StepResult, error) {
	if grant.PlanID != p.PlanID || grant.PlanHash != p.PlanHash {
		return model.StepResult{}, refuse("approval_invalid", "approval does not match the plan")
	}
	if !time.Now().Before(grant.ExpiresAt.Time) {
		return model.StepResult{}, refuse("approval_expired", "approval has expired")
	}
	switch req.ActionName() {
	case "filesystem.quarantine":
		params, ok := req.Typed.(*protocol.FilesystemQuarantineParams)
		if !ok {
			return model.StepResult{}, refuse("executor_refused", "invalid quarantine params")
		}
		return e.quarantine(params.PlanTargetParams, p, grant)
	case "filesystem.restore":
		params, ok := req.Typed.(*protocol.FilesystemRestoreParams)
		if !ok {
			return model.StepResult{}, refuse("executor_refused", "invalid restore params")
		}
		return e.restore(params.PlanTargetParams, p)
	default:
		return model.StepResult{}, refuse("executor_refused", "%s is not a mutation action", req.ActionName())
	}
}

func (e *QuarantineExecutor) quarantine(params protocol.PlanTargetParams, p plan.Plan, grant plan.Grant) (model.StepResult, error) {
	step, err := p.StepFor(params.CandidateID, params.Path)
	if err != nil {
		return model.StepResult{}, refuse("scope_mismatch", "%s", err.Error())
	}
	if len(p.Steps) > p.Limits.MaxItems {
		return model.StepResult{}, refuse("limit_exceeded", "plan exceeds max_items")
	}
	if p.TotalBytes() > p.Limits.MaxBytes {
		return model.StepResult{}, refuse("limit_exceeded", "plan exceeds max_bytes")
	}
	source := step.Path
	if !underRoot(source, p.Roots) {
		return model.StepResult{}, refuse("scope_mismatch", "target is outside the approved roots")
	}
	info, err := os.Lstat(source)
	if err != nil {
		return model.StepResult{}, refuse("target_missing", "cannot stat %s: %v", source, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return model.StepResult{}, refuse("target_changed", "symlinks are never quarantined")
	}
	if err := verifyIdentity(info, step); err != nil {
		return model.StepResult{}, err
	}

	base := filepath.Join(e.Dir, p.PlanID, step.CandidateID)
	payload := filepath.Join(base, "payload")
	metaPath := filepath.Join(base, "meta.json")
	if _, err := os.Lstat(base); err == nil {
		return model.StepResult{}, refuse("plan_replayed", "quarantine slot already exists: %s", base)
	}
	if err := os.MkdirAll(base, 0o700); err != nil {
		return model.StepResult{}, err
	}
	baseInfo, err := os.Stat(base)
	if err != nil {
		return model.StepResult{}, err
	}
	if st, ok := baseInfo.Sys().(*syscall.Stat_t); !ok || st.Dev != step.Dev {
		os.Remove(base)
		return model.StepResult{}, refuse("cross_device", "quarantine is on a different filesystem")
	}
	if err := renameNoReplace(source, payload); err != nil {
		os.RemoveAll(base)
		return model.StepResult{}, refuse("executor_refused", "rename failed: %v", err)
	}

	record := model.QuarantineRecord{
		PlanID: p.PlanID, PlanHash: p.PlanHash, CandidateID: step.CandidateID,
		OriginalPath: step.Path, Dev: step.Dev, Ino: step.Ino,
		SizeBytes: step.SizeBytes, MtimeNS: step.MtimeNS, Mode: step.Mode,
		UID: step.UID, QuarantinedAt: model.Timestamp{Time: time.Now().UTC().Truncate(time.Microsecond)},
		ApprovedBy: grant.ApprovedBy,
	}
	if err := writeMeta(metaPath, record); err != nil {
		_ = renameNoReplace(payload, source)
		os.Remove(base)
		return model.StepResult{}, refuse("executor_refused", "cannot write sidecar: %v", err)
	}
	path := payload
	return model.StepResult{
		Action: "filesystem.quarantine", CandidateID: step.CandidateID,
		Path: step.Path, Status: "quarantined", QuarantinePath: &path,
		BytesMoved: step.SizeBytes,
	}, nil
}

func (e *QuarantineExecutor) restore(params protocol.PlanTargetParams, p plan.Plan) (model.StepResult, error) {
	step, err := p.StepFor(params.CandidateID, params.Path)
	if err != nil {
		return model.StepResult{}, refuse("scope_mismatch", "%s", err.Error())
	}
	base := filepath.Join(e.Dir, p.PlanID, step.CandidateID)
	payload := filepath.Join(base, "payload")
	metaPath := filepath.Join(base, "meta.json")
	if _, err := os.Lstat(metaPath); err != nil {
		return model.StepResult{}, refuse("target_missing", "no quarantine record for %s", step.CandidateID)
	}
	raw, err := os.ReadFile(metaPath)
	if err != nil {
		return model.StepResult{}, err
	}
	var record model.QuarantineRecord
	if err := model.DecodeStrict(raw, &record); err != nil {
		return model.StepResult{}, refuse("executor_refused", "invalid quarantine record: %v", err)
	}
	if record.PlanID != p.PlanID || record.PlanHash != p.PlanHash {
		return model.StepResult{}, refuse("scope_mismatch", "quarantine record does not match this plan")
	}
	if record.OriginalPath != step.Path {
		return model.StepResult{}, refuse("scope_mismatch", "restore target does not match the plan")
	}
	payloadInfo, err := os.Lstat(payload)
	if err != nil {
		return model.StepResult{}, refuse("target_missing", "quarantined payload is missing")
	}
	if err := verifyRecordIdentity(payloadInfo, record); err != nil {
		return model.StepResult{}, err
	}
	target := record.OriginalPath
	parent := filepath.Dir(target)
	parentInfo, err := os.Stat(parent)
	if err != nil || !parentInfo.IsDir() {
		return model.StepResult{}, refuse("target_missing", "original parent is missing: %s", parent)
	}
	if _, err := os.Lstat(target); err == nil {
		return model.StepResult{}, refuse("target_changed", "restore target already exists: %s", target)
	}
	payloadDev, ok := deviceOfPath(payload)
	if !ok {
		return model.StepResult{}, refuse("target_missing", "cannot stat quarantined payload")
	}
	parentDev, err := deviceOf(parent)
	if err != nil || parentDev != payloadDev {
		return model.StepResult{}, refuse("cross_device", "restore crosses filesystems")
	}
	if err := renameNoReplace(payload, target); err != nil {
		return model.StepResult{}, refuse("executor_refused", "restore rename failed: %v", err)
	}
	restored := filepath.Join(base, "meta.restored-"+time.Now().Format("20060102150405")+".json")
	_ = os.Rename(metaPath, restored)
	path := payload
	return model.StepResult{
		Action: "filesystem.restore", CandidateID: step.CandidateID,
		Path: record.OriginalPath, Status: "restored", QuarantinePath: &path,
		BytesMoved: record.SizeBytes,
	}, nil
}

func writeMeta(path string, record model.QuarantineRecord) error {
	tmp := filepath.Join(filepath.Dir(path), fmt.Sprintf(".meta-%d.tmp", os.Getpid()))
	flags := os.O_WRONLY | os.O_CREATE | os.O_EXCL | syscall.O_NOFOLLOW
	fd, err := os.OpenFile(tmp, flags, 0o600)
	if err != nil {
		return err
	}
	fail := func(err error) error {
		fd.Close()
		os.Remove(tmp)
		return err
	}
	payload, err := json.Marshal(record)
	if err != nil {
		return fail(err)
	}
	if _, err := fd.Write(payload); err != nil {
		return fail(err)
	}
	if err := fd.Sync(); err != nil {
		return fail(err)
	}
	if err := fd.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}

func verifyIdentity(info os.FileInfo, step plan.Step) error {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return refuse("target_changed", "cannot read target identity")
	}
	if !info.Mode().IsRegular() {
		return refuse("target_changed", "%s is not a regular file", step.Path)
	}
	if st.Dev != step.Dev || st.Ino != step.Ino || info.Size() != step.SizeBytes ||
		info.ModTime().UnixNano() != step.MtimeNS || st.Mode != step.Mode || st.Uid != step.UID {
		return refuse("target_changed", "%s changed since the plan was approved", step.Path)
	}
	return nil
}

func verifyRecordIdentity(info os.FileInfo, record model.QuarantineRecord) error {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return refuse("target_changed", "cannot read payload identity")
	}
	if !info.Mode().IsRegular() {
		return refuse("target_changed", "quarantined payload is not a regular file")
	}
	if st.Dev != record.Dev || st.Ino != record.Ino || info.Size() != record.SizeBytes ||
		info.ModTime().UnixNano() != record.MtimeNS || st.Mode != record.Mode || st.Uid != record.UID {
		return refuse("target_changed", "quarantined payload changed")
	}
	return nil
}

func deviceOfPath(path string) (uint64, bool) {
	info, err := os.Stat(path)
	if err != nil {
		return 0, false
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return st.Dev, true
}

func underRoot(path string, roots []string) bool {
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		resolved = filepath.Clean(path)
	}
	for _, root := range roots {
		rootPath, err := filepath.EvalSymlinks(root)
		if err != nil {
			rootPath = filepath.Clean(root)
		}
		if resolved == rootPath || strings.HasPrefix(resolved, strings.TrimSuffix(rootPath, "/")+"/") {
			return true
		}
	}
	return false
}

// ExecutorActions is the fixed set the dispatcher serves.
func ExecutorActions() []string {
	return []string{"filesystem.quarantine", "filesystem.restore", "process.signal", "network.prefer"}
}

var errRenameUnavailable = errors.New("renameat2 is not available on this platform")
