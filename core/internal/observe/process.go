// Package observe implements the read-only system observers.
//
// Everything in this package reads procfs/sysfs. Nothing opens a socket,
// executes a command, or writes a file. Observers are deliberately tolerant
// of paths vanishing mid-scan: a process can exit at any moment, and one
// unreadable entry must not fail the whole snapshot.
package observe

import (
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"aios/internal/model"
)

const (
	procClkTck   = 100
	procPageSize = 4096
)

// ProcessInfo is one process view. Nullable fields are pointers without
// omitempty so the JSON shape always contains the key with a null value.
type ProcessInfo struct {
	PID              int              `json:"pid"`
	PPID             int              `json:"ppid"`
	Name             string           `json:"name"`
	State            string           `json:"state"`
	StateDescription string           `json:"state_description"`
	UID              *int             `json:"uid"`
	GID              *int             `json:"gid"`
	Threads          *int             `json:"threads"`
	VsizeBytes       *int64           `json:"vsize_bytes"`
	RSSBytes         *int64           `json:"rss_bytes"`
	RSSPercent       *float64         `json:"rss_percent"`
	CPUPercent       *float64         `json:"cpu_percent"`
	StartTimeUTC     *string          `json:"start_time_utc"`
	ElapsedS         *float64         `json:"elapsed_s"`
	Cmdline          []string         `json:"cmdline"`
	Executable       *string          `json:"executable"`
	Cwd              *string          `json:"cwd"`
	UIDReal          *int             `json:"uid_real"`
	ThreadsList      []int            `json:"threads_list"`
	IO               map[string]int64 `json:"io"`
	Limits           map[string]any   `json:"limits"`
	Sched            map[string]int64 `json:"sched"`
	Cgroup           *string          `json:"cgroup"`
}

// ProcessListResult is a sorted, truncated process snapshot.
type ProcessListResult struct {
	Processes           []ProcessInfo       `json:"processes"`
	TotalFound          int                 `json:"total_found"`
	Returned            int                 `json:"returned"`
	Skipped             []map[string]string `json:"skipped"`
	CPUPercentAvailable bool                `json:"cpu_percent_available"`
	MemoryTotalKB       *int64              `json:"memory_total_kb"`
}

// ProcessNotFoundError reports a pid that could not be read or is not
// inspectable. It mirrors Python's ProcessNotFound LookupError.
type ProcessNotFoundError struct {
	PID    int
	Reason string
}

func (e *ProcessNotFoundError) Error() string {
	return fmt.Sprintf("pid %d is not readable: %s", e.PID, e.Reason)
}

var procStateDescription = map[string]string{
	"R": "running",
	"S": "sleeping (interruptible)",
	"D": "uninterruptible sleep (often I/O wait)",
	"Z": "zombie",
	"T": "stopped (job control)",
	"t": "tracing stop",
	"X": "dead",
	"x": "dead",
	"K": "wakekill",
	"W": "waking",
	"P": "parked",
	"I": "idle",
}

// procNonInspectable are states with no meaningful user-space identity.
var procNonInspectable = map[string]bool{"Z": true, "X": true, "x": true}

// procLimitLabels are the fixed labels in /proc/<pid>/limits. The table is
// fixed-width, not whitespace delimited, because labels contain spaces.
var procLimitLabels = map[string]bool{
	"Max cpu time":          true,
	"Max file size":         true,
	"Max data size":         true,
	"Max stack size":        true,
	"Max core file size":    true,
	"Max resident set":      true,
	"Max processes":         true,
	"Max open files":        true,
	"Max locked memory":     true,
	"Max address space":     true,
	"Max file locks":        true,
	"Max pending signals":   true,
	"Max msgqueue size":     true,
	"Max nice priority":     true,
	"Max realtime priority": true,
	"Max realtime timeout":  true,
}

type procStat struct {
	PID        int
	Comm       string
	State      string
	PPID       int
	NumThreads int
	Utime      int64
	Stime      int64
	Starttime  *int64
	Vsize      *int64
	RSS        *int64
}

// procParseStat parses /proc/<pid>/stat. Field 2 (comm) is enclosed in
// parentheses and may itself contain both spaces and parentheses, so the
// name is extracted by locating the last ')' rather than splitting on space.
func procParseStat(text string) (procStat, error) {
	trimmed := strings.TrimSpace(text)
	open := strings.IndexByte(trimmed, '(')
	closeIdx := strings.LastIndexByte(trimmed, ')')
	if open <= 0 || closeIdx < open {
		return procStat{}, fmt.Errorf("unparsable /proc/<pid>/stat line")
	}
	pidText := strings.TrimSpace(trimmed[:open])
	pid, err := strconv.Atoi(pidText)
	if err != nil {
		return procStat{}, fmt.Errorf("unparsable /proc/<pid>/stat pid: %q", pidText)
	}
	comm := trimmed[open+1 : closeIdx]
	fields := strings.Fields(trimmed[closeIdx+1:])
	if len(fields) < 22 {
		return procStat{}, fmt.Errorf("short /proc/<pid>/stat: %d fields after comm", len(fields))
	}
	return procStat{
		PID:        pid,
		Comm:       comm,
		State:      fields[0],
		PPID:       procAtoi(fields[1]),
		Utime:      procAtoi64(fields[11]),
		Stime:      procAtoi64(fields[12]),
		NumThreads: procAtoi(fields[17]),
		Starttime:  procInt64Ptr(fields[19]),
		Vsize:      procInt64Ptr(fields[20]),
		RSS:        procInt64Ptr(fields[21]),
	}, nil
}

type procStatus struct {
	UID *int
	GID *int
}

func procParseStatus(text string) procStatus {
	var out procStatus
	for _, line := range strings.Split(text, "\n") {
		idx := strings.IndexByte(line, ':')
		if idx < 0 {
			continue
		}
		key := strings.TrimSpace(line[:idx])
		value := strings.TrimSpace(line[idx+1:])
		switch key {
		case "Uid":
			out.UID = procFirstInt(value)
		case "Gid":
			out.GID = procFirstInt(value)
		}
	}
	return out
}

func procFirstInt(value string) *int {
	for _, part := range strings.Fields(value) {
		if part == "" {
			continue
		}
		if n, err := strconv.Atoi(part); err == nil {
			return &n
		}
	}
	return nil
}

func procAtoi(value string) int {
	n, err := strconv.Atoi(value)
	if err != nil {
		return 0
	}
	return n
}

func procAtoi64(value string) int64 {
	n, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		return 0
	}
	return n
}

func procInt64Ptr(value string) *int64 {
	n, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		return nil
	}
	return &n
}

func procIntPtr(n int) *int { return &n }

func procStringPtr(s string) *string { return &s }

func procFloatPtr(f float64) *float64 { return &f }

// procReadLimited reads at most max bytes of text, replacing invalid UTF-8.
// It errors rather than truncating when the file is larger than max, matching
// Python's read_text ceiling for kernel pseudo-files.
func procReadLimited(path string, max int) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	data, err := io.ReadAll(io.LimitReader(f, int64(max)+1))
	if err != nil {
		return "", err
	}
	if len(data) > max {
		return "", fmt.Errorf("%s exceeds read limit of %d bytes", path, max)
	}
	return strings.ToValidUTF8(string(data), "\uFFFD"), nil
}

func procParseCmdline(raw string) []string {
	parts := strings.Split(raw, "\x00")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func procResolveLink(path string) (string, error) {
	target, err := os.Readlink(path)
	if err != nil {
		return "", err
	}
	if !filepath.IsAbs(target) {
		target = filepath.Join(filepath.Dir(path), target)
	}
	if resolved, err := filepath.EvalSymlinks(target); err == nil {
		target = resolved
	}
	if abs, err := filepath.Abs(target); err == nil {
		target = abs
	}
	return filepath.Clean(target), nil
}

func procReadThreads(base string) []int {
	entries, err := os.ReadDir(filepath.Join(base, "task"))
	if err != nil {
		return []int{}
	}
	out := make([]int, 0, len(entries))
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}
		out = append(out, pid)
	}
	sort.Ints(out)
	return out
}

func procReadCgroup(base string) *string {
	text, err := procReadLimited(filepath.Join(base, "cgroup"), 8192)
	if err != nil {
		return nil
	}
	trimmed := strings.TrimSpace(text)
	if trimmed == "" {
		return nil
	}
	first := strings.Split(trimmed, "\n")[0]
	if len(first) > 256 {
		first = first[:256]
	}
	return procStringPtr(first)
}

func procReadIO(base string) map[string]int64 {
	text, err := procReadLimited(filepath.Join(base, "io"), 8192)
	if err != nil {
		return nil
	}
	out := map[string]int64{}
	for _, line := range strings.Split(text, "\n") {
		idx := strings.IndexByte(line, ':')
		if idx < 0 {
			continue
		}
		key := strings.TrimSpace(line[:idx])
		value := strings.TrimSpace(line[idx+1:])
		n, err := strconv.ParseInt(value, 10, 64)
		if err != nil {
			continue
		}
		out[key] = n
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func procReadSched(base string) map[string]int64 {
	text, err := procReadLimited(filepath.Join(base, "schedstat"), 1024)
	if err != nil {
		return nil
	}
	parts := strings.Fields(text)
	if len(parts) == 0 {
		return nil
	}
	names := []string{"time_on_cpu_ns", "run_queue_wait_ns", "timeslices"}
	out := map[string]int64{}
	for i, name := range names {
		if i >= len(parts) {
			break
		}
		n, err := strconv.ParseInt(parts[i], 10, 64)
		if err != nil {
			continue
		}
		out[name] = n
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// procParseLimits reads the soft limit column only. Hard limits describe what
// a process could escalate to, not what it may currently do.
func procParseLimits(text string) map[string]any {
	out := map[string]any{}
	for _, line := range strings.Split(text, "\n") {
		var label, value string
		if idx := strings.IndexByte(line, '|'); idx >= 0 {
			label = strings.TrimSpace(line[:idx])
			rest := line[idx+1:]
			if j := strings.IndexByte(rest, '|'); j >= 0 {
				rest = rest[:j]
			}
			value = strings.TrimSpace(rest)
		} else {
			label = strings.TrimSpace(procSlice(line, 0, 26))
			if !procLimitLabels[label] {
				continue
			}
			value = strings.TrimSpace(procSlice(line, 26, 47))
		}
		if label == "" || label == "Limit" {
			continue
		}
		if value == "unlimited" {
			out[label] = "unlimited"
			continue
		}
		if n, err := strconv.Atoi(value); err == nil {
			out[label] = n
		}
	}
	return out
}

func procReadLimits(base string) map[string]any {
	text, err := procReadLimited(filepath.Join(base, "limits"), 16384)
	if err != nil {
		return map[string]any{}
	}
	return procParseLimits(text)
}

func procSlice(value string, start, end int) string {
	if start > len(value) {
		start = len(value)
	}
	if end > len(value) {
		end = len(value)
	}
	if end < start {
		end = start
	}
	return value[start:end]
}

func procReadUptime(procRoot string) (float64, bool) {
	text, err := procReadLimited(filepath.Join(procRoot, "uptime"), 4096)
	if err != nil {
		return 0, false
	}
	fields := strings.Fields(text)
	if len(fields) == 0 {
		return 0, false
	}
	value, err := strconv.ParseFloat(fields[0], 64)
	if err != nil {
		return 0, false
	}
	return value, true
}

func procElapsed(starttime *int64, uptime float64) *float64 {
	if starttime == nil {
		return nil
	}
	elapsed := uptime - float64(*starttime)/procClkTck
	if elapsed < 0 {
		elapsed = 0
	}
	return procFloatPtr(procRound2(elapsed))
}

func procRound2(value float64) float64 {
	return math.Round(value*100) / 100
}

func procInspect(procRoot string, pid int, withExtras, enforceInspectable bool, uptime *float64) (ProcessInfo, error) {
	if pid <= 0 {
		return ProcessInfo{}, &ProcessNotFoundError{PID: pid, Reason: "invalid pid"}
	}
	base := filepath.Join(procRoot, strconv.Itoa(pid))

	statText, err := procReadLimited(filepath.Join(base, "stat"), 8192)
	if err != nil {
		return ProcessInfo{}, &ProcessNotFoundError{PID: pid, Reason: err.Error()}
	}
	stat, err := procParseStat(statText)
	if err != nil {
		return ProcessInfo{}, &ProcessNotFoundError{PID: pid, Reason: err.Error()}
	}
	if enforceInspectable && procNonInspectable[stat.State] {
		return ProcessInfo{}, &ProcessNotFoundError{
			PID:    pid,
			Reason: fmt.Sprintf("state %s is not inspectable", stat.State),
		}
	}

	var status procStatus
	if statusText, err := procReadLimited(filepath.Join(base, "status"), 32768); err == nil {
		status = procParseStatus(statusText)
	}

	cmdline := []string{}
	executable := (*string)(nil)
	if raw, err := procReadLimited(filepath.Join(base, "cmdline"), 131072); err == nil {
		cmdline = procParseCmdline(raw)
		if len(cmdline) > 0 {
			executable = procStringPtr(cmdline[0])
		}
	}

	var cwd *string
	if withExtras {
		if resolved, err := procResolveLink(filepath.Join(base, "cwd")); err == nil {
			cwd = procStringPtr(resolved)
		}
		if resolved, err := procResolveLink(filepath.Join(base, "exe")); err == nil {
			executable = procStringPtr(filepath.Base(resolved))
		}
	}

	info := ProcessInfo{
		PID:              pid,
		PPID:             stat.PPID,
		Name:             stat.Comm,
		State:            stat.State,
		StateDescription: procStateDescription[stat.State],
		UID:              status.UID,
		GID:              status.GID,
		VsizeBytes:       stat.Vsize,
		Cmdline:          cmdline,
		Executable:       executable,
		Cwd:              cwd,
		ThreadsList:      procReadThreads(base),
		Limits:           map[string]any{},
		Cgroup:           procReadCgroup(base),
	}
	if info.StateDescription == "" {
		info.StateDescription = "unknown"
	}
	if stat.NumThreads != 0 {
		info.Threads = procIntPtr(stat.NumThreads)
	}
	if stat.RSS != nil {
		rss := *stat.RSS * procPageSize
		info.RSSBytes = &rss
	}
	if withExtras {
		info.IO = procReadIO(base)
		info.Limits = procReadLimits(base)
		info.Sched = procReadSched(base)
	}
	if uptime != nil {
		info.ElapsedS = procElapsed(stat.Starttime, *uptime)
	}
	return info, nil
}

// ReadProcessInspect returns a detailed view of one process. PIDs in a
// non-inspectable state (zombie/dead) are rejected: there is no user-space
// identity left to reason about.
func ReadProcessInspect(procRoot string, pid int, includeExtras bool) (ProcessInfo, error) {
	var uptime *float64
	if value, ok := procReadUptime(procRoot); ok {
		uptime = &value
	}
	return procInspect(procRoot, pid, includeExtras, true, uptime)
}

// ReadProcessList returns a sorted, filtered process snapshot. A process that
// vanishes or whose stat is unreadable is recorded in skipped, never fatal.
func ReadProcessList(procRoot string, limit int, sortBy string, nameFilter *string, uidFilter *int, includeCmdline bool) (ProcessListResult, error) {
	if limit <= 0 {
		return ProcessListResult{}, fmt.Errorf("limit must be positive")
	}
	switch sortBy {
	case "cpu", "memory", "pid", "name":
	default:
		return ProcessListResult{}, fmt.Errorf("unsupported sort_by: %s", sortBy)
	}

	result := ProcessListResult{
		Processes: []ProcessInfo{},
		Skipped:   []map[string]string{},
	}

	entries, err := os.ReadDir(procRoot)
	if err != nil {
		return result, nil
	}
	pids := make([]int, 0, len(entries))
	for _, entry := range entries {
		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}
		pids = append(pids, pid)
	}
	sort.Ints(pids)

	var uptime *float64
	if value, ok := procReadUptime(procRoot); ok {
		uptime = &value
	}

	for _, pid := range pids {
		info, err := procInspect(procRoot, pid, false, false, uptime)
		if err != nil {
			reason := err.Error()
			if len(reason) > 200 {
				reason = reason[:200]
			}
			result.Skipped = append(result.Skipped, map[string]string{
				"pid":    strconv.Itoa(pid),
				"reason": reason,
			})
			continue
		}
		if nameFilter != nil && *nameFilter != "" {
			if !strings.Contains(strings.ToLower(info.Name), strings.ToLower(*nameFilter)) {
				continue
			}
		}
		if uidFilter != nil && (info.UID == nil || *info.UID != *uidFilter) {
			continue
		}
		// The Python reference re-inspects when include_cmdline is set, but
		// cmdline is always populated by inspect; keep the parameter for API
		// compatibility and avoid the redundant /proc read.
		_ = includeCmdline
		result.Processes = append(result.Processes, info)
	}

	switch sortBy {
	case "cpu":
		sort.SliceStable(result.Processes, func(i, j int) bool {
			return procDerefFloat(result.Processes[i].CPUPercent) > procDerefFloat(result.Processes[j].CPUPercent)
		})
	case "memory":
		sort.SliceStable(result.Processes, func(i, j int) bool {
			return procDerefInt64(result.Processes[i].RSSBytes) > procDerefInt64(result.Processes[j].RSSBytes)
		})
	case "name":
		sort.SliceStable(result.Processes, func(i, j int) bool {
			return strings.ToLower(result.Processes[i].Name) < strings.ToLower(result.Processes[j].Name)
		})
	default: // "pid"
		sort.SliceStable(result.Processes, func(i, j int) bool {
			return result.Processes[i].PID < result.Processes[j].PID
		})
	}

	for _, info := range result.Processes {
		if info.CPUPercent != nil {
			result.CPUPercentAvailable = true
			break
		}
	}

	result.TotalFound = len(result.Processes)
	if len(result.Processes) > limit {
		result.Processes = result.Processes[:limit]
	}
	result.Returned = len(result.Processes)
	return result, nil
}

func procDerefFloat(value *float64) float64 {
	if value == nil {
		return 0
	}
	return *value
}

func procDerefInt64(value *int64) int64 {
	if value == nil {
		return 0
	}
	return *value
}

// ProcessIdentity is the immutable-ish identity captured in a process plan.
// StartTicks comes from /proc/<pid>/stat field 22 and, together with the pid,
// closes the PID-reuse window: a reused pid has a different start time.
type ProcessIdentity struct {
	PID          int     `json:"pid"`
	PPID         int     `json:"ppid"`
	Name         string  `json:"name"`
	State        string  `json:"state"`
	UID          int     `json:"uid"`
	StartTicks   int64   `json:"start_ticks"`
	StartTimeUTC *string `json:"start_time_utc"`
	Executable   *string `json:"executable"`
}

// ReadProcessIdentity captures the identity fields a signal plan binds to.
// Unlike ReadProcessInspect it accepts zombies: diagnosing them is the point.
func ReadProcessIdentity(procRoot string, pid int) (ProcessIdentity, error) {
	if pid <= 0 {
		return ProcessIdentity{}, &ProcessNotFoundError{PID: pid, Reason: "invalid pid"}
	}
	base := filepath.Join(procRoot, strconv.Itoa(pid))
	statText, err := procReadLimited(filepath.Join(base, "stat"), 8192)
	if err != nil {
		return ProcessIdentity{}, &ProcessNotFoundError{PID: pid, Reason: err.Error()}
	}
	stat, err := procParseStat(statText)
	if err != nil {
		return ProcessIdentity{}, &ProcessNotFoundError{PID: pid, Reason: err.Error()}
	}
	if stat.Starttime == nil {
		return ProcessIdentity{}, &ProcessNotFoundError{PID: pid, Reason: "start time is unavailable"}
	}
	var status procStatus
	if statusText, err := procReadLimited(filepath.Join(base, "status"), 32768); err == nil {
		status = procParseStatus(statusText)
	}
	identity := ProcessIdentity{
		PID: pid, PPID: stat.PPID, Name: stat.Comm, State: stat.State,
		StartTicks: *stat.Starttime,
	}
	if status.UID != nil {
		identity.UID = *status.UID
	}
	if uptime, ok := procReadUptime(procRoot); ok {
		started := time.Now().Add(-time.Duration((uptime - float64(*stat.Starttime)/procClkTck) * float64(time.Second)))
		text := started.UTC().Truncate(time.Second).Format(time.RFC3339)
		identity.StartTimeUTC = &text
	}
	if raw, err := procReadLimited(filepath.Join(base, "cmdline"), 131072); err == nil {
		cmdline := procParseCmdline(raw)
		if len(cmdline) > 0 {
			identity.Executable = procStringPtr(cmdline[0])
		}
	}
	if resolved, err := procResolveLink(filepath.Join(base, "exe")); err == nil {
		identity.Executable = procStringPtr(resolved)
	}
	return identity, nil
}

// ProcessFinding is one diagnosis row.
type ProcessFinding struct {
	PID            int      `json:"pid"`
	PPID           int      `json:"ppid"`
	Name           string   `json:"name"`
	State          string   `json:"state"`
	StateText      string   `json:"state_description"`
	UID            *int     `json:"uid"`
	StartTimeUTC   *string  `json:"start_time_utc"`
	ElapsedS       *float64 `json:"elapsed_s"`
	CPUPercent     *float64 `json:"cpu_percent"`
	RSSBytes       *int64   `json:"rss_bytes"`
	ParentName     *string  `json:"parent_name"`
	ParentState    *string  `json:"parent_state"`
	Reason         string   `json:"reason"`
	Recommendation string   `json:"recommendation"`
}

// ProcessDiagnosis is the read-only result of process.diagnose.
type ProcessDiagnosis struct {
	GeneratedAt  model.Timestamp  `json:"generated_at"`
	TotalScanned int              `json:"total_scanned"`
	Zombies      []ProcessFinding `json:"zombies"`
	Orphans      []ProcessFinding `json:"orphans"`
	TopCPU       []ProcessFinding `json:"top_cpu"`
	TopMemory    []ProcessFinding `json:"top_memory"`
	Notes        []string         `json:"notes"`
}

// DiagnoseProcesses classifies zombies and adopted/orphaned processes without
// changing anything. A zombie has no live identity and cannot be killed; its
// parent must reap it. An orphan is alive and merely reparented.
func DiagnoseProcesses(procRoot string, limit int, uidFilter *int, includeOrphans bool, topN int) (ProcessDiagnosis, error) {
	if limit < 1 {
		limit = 200
	}
	if topN < 0 {
		topN = 0
	}
	snapshot, err := ReadProcessList(procRoot, 5000, "pid", nil, uidFilter, false)
	if err != nil {
		return ProcessDiagnosis{}, err
	}
	byPID := make(map[int]ProcessInfo, len(snapshot.Processes))
	for _, info := range snapshot.Processes {
		byPID[info.PID] = info
	}
	diagnosis := ProcessDiagnosis{
		GeneratedAt:  model.Timestamp{Time: time.Now().UTC().Truncate(time.Microsecond)},
		TotalScanned: len(snapshot.Processes),
		Zombies:      []ProcessFinding{},
		Orphans:      []ProcessFinding{},
		TopCPU:       []ProcessFinding{},
		TopMemory:    []ProcessFinding{},
		Notes: []string{
			"A zombie is already dead. It cannot be killed; its parent must call wait() or be restarted.",
			"An orphan has been reparented to init. It is alive, not a zombie, and can be signalled if it is unwanted.",
			"Signals are limited to processes owned by the core's user.",
		},
	}
	finding := func(info ProcessInfo) ProcessFinding {
		out := ProcessFinding{
			PID: info.PID, PPID: info.PPID, Name: info.Name, State: info.State,
			StateText: info.StateDescription, UID: info.UID,
			StartTimeUTC: info.StartTimeUTC, ElapsedS: info.ElapsedS,
			CPUPercent: info.CPUPercent, RSSBytes: info.RSSBytes,
		}
		if parent, ok := byPID[info.PPID]; ok {
			out.ParentName = procStringPtr(parent.Name)
			out.ParentState = procStringPtr(parent.State)
		}
		return out
	}
	for _, info := range snapshot.Processes {
		if info.State == "Z" {
			row := finding(info)
			row.Reason = "zombie: the process has exited but its parent has not reaped it"
			if row.ParentName != nil {
				row.Recommendation = "parent " + *row.ParentName + " (pid " + strconv.Itoa(info.PPID) + ") must call wait() or be restarted; killing the zombie is not possible"
			} else {
				row.Recommendation = "the parent is gone; a service manager or init should reap it"
			}
			diagnosis.Zombies = append(diagnosis.Zombies, row)
			continue
		}
		if !includeOrphans || info.PID == 1 {
			continue
		}
		_, parentExists := byPID[info.PPID]
		if info.PPID == 1 || info.PPID == 0 || !parentExists {
			row := finding(info)
			row.Reason = "orphan: reparented to init after its original parent exited"
			row.Recommendation = "leave it if it is a service; otherwise propose process.signal with its pid"
			diagnosis.Orphans = append(diagnosis.Orphans, row)
		}
	}
	if len(diagnosis.Orphans) > limit {
		diagnosis.Orphans = diagnosis.Orphans[:limit]
	}
	if topN > 0 {
		cpu := append([]ProcessInfo(nil), snapshot.Processes...)
		sort.SliceStable(cpu, func(i, j int) bool {
			return procDerefFloat(cpu[i].CPUPercent) > procDerefFloat(cpu[j].CPUPercent)
		})
		for _, info := range cpu[:min(topN, len(cpu))] {
			diagnosis.TopCPU = append(diagnosis.TopCPU, finding(info))
		}
		mem := append([]ProcessInfo(nil), snapshot.Processes...)
		sort.SliceStable(mem, func(i, j int) bool {
			return procDerefInt64(mem[i].RSSBytes) > procDerefInt64(mem[j].RSSBytes)
		})
		for _, info := range mem[:min(topN, len(mem))] {
			diagnosis.TopMemory = append(diagnosis.TopMemory, finding(info))
		}
	}
	return diagnosis, nil
}
