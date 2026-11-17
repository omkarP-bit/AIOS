// Package gateway is the only path from an authorized read action to Linux.
//
// It is a fixed whitelist: one handler per read-only action, no dynamic
// dispatch, no shell, no fallback. Every handler re-checks its own
// preconditions even though the engine has already decided.
package gateway

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"aios/internal/actions"
	"aios/internal/catalog"
	"aios/internal/model"
	"aios/internal/observe"
	"aios/internal/protocol"
)

// Envelope wraps every observation so provenance is never inferred.
type Envelope struct {
	Source      string          `json:"source"`
	Origin      string          `json:"origin"`
	TrustDomain string          `json:"trust_domain"`
	Timestamp   model.Timestamp `json:"timestamp"`
	Type        string          `json:"type"`
	Data        any             `json:"data"`
}

// Trusted reports whether the envelope is inside the boundary.
func (e Envelope) Trusted() bool {
	return e.TrustDomain == "T0" || e.TrustDomain == "T1" || e.TrustDomain == "T2"
}

func envelope(source, origin, trust, action string, data any) *Envelope {
	return &Envelope{
		Source: source, Origin: origin, TrustDomain: trust,
		Timestamp: model.Timestamp{Time: time.Now().UTC().Truncate(time.Microsecond)},
		Type:      action, Data: data,
	}
}

// GatewayError is a structural refusal.
type GatewayError struct{ Message string }

func (e GatewayError) Error() string { return e.Message }

// ActionNotPermitted means the action is not in the whitelist at all.
type ActionNotPermitted struct{ GatewayError }

// PreconditionFailed means the action is whitelisted but the target is not
// readable right now.
type PreconditionFailed struct{ GatewayError }

func fail(format string, args ...any) PreconditionFailed {
	return PreconditionFailed{GatewayError{Message: fmt.Sprintf(format, args...)}}
}

// Gateway serves the read-only catalog.
type Gateway struct {
	ProcRoot      string
	SysRoot       string
	MaxReadBytes  int
	MaxDirEntries int
	QuarantineDir string
	handlers      map[string]bool
}

// New builds a gateway over the given procfs/sysfs roots.
func New(procRoot, sysRoot, quarantineDir string) *Gateway {
	if procRoot == "" {
		procRoot = "/proc"
	}
	if sysRoot == "" {
		sysRoot = filepath.Join(filepath.Dir(procRoot), "sys")
	}
	g := &Gateway{
		ProcRoot: procRoot, SysRoot: sysRoot,
		MaxReadBytes: 1 << 20, MaxDirEntries: 2000, QuarantineDir: quarantineDir,
		handlers: map[string]bool{},
	}
	for name, descriptor := range catalog.Catalog {
		if descriptor.ReadOnly && !catalog.ExecutorActions[name] {
			g.handlers[name] = true
		}
	}
	return g
}

// SupportedActions is the closed read-only set.
func (g *Gateway) SupportedActions() []string {
	names := make([]string, 0, len(g.handlers))
	for name := range g.handlers {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// Supports reports whether the gateway serves an action.
func (g *Gateway) Supports(action string) bool { return g.handlers[action] }

// Execute runs one already-authorized read.
func (g *Gateway) Execute(req *protocol.Request) (*Envelope, error) {
	name := req.ActionName()
	if !g.handlers[name] {
		return nil, ActionNotPermitted{GatewayError{Message: "action " + name + " is not in the gateway whitelist"}}
	}
	switch name {
	case "system.cpu":
		p, ok := req.Typed.(*protocol.SystemCPUParams)
		if !ok {
			return nil, fail("invalid cpu params")
		}
		info, err := observe.ReadCPU(g.ProcRoot, g.SysRoot, p.IntervalS, p.IncludeFrequencies)
		if err != nil {
			return nil, fail("cannot read cpu: %v", err)
		}
		return envelope("procfs:"+g.ProcRoot+"/stat", "gateway", "T2", name, info), nil

	case "system.memory":
		p, ok := req.Typed.(*protocol.SystemMemoryParams)
		if !ok {
			return nil, fail("invalid memory params")
		}
		info, err := observe.ReadMemory(g.ProcRoot, p.IncludeSwap, p.IncludeFields)
		if err != nil {
			return nil, fail("cannot read memory: %v", err)
		}
		return envelope("procfs:"+g.ProcRoot+"/meminfo", "gateway", "T2", name, info), nil

	case "system.hostname":
		info, err := observe.ReadSystem(g.ProcRoot, g.SysRoot, true, true)
		if err != nil {
			return nil, fail("cannot read system: %v", err)
		}
		fields := asMap(info)
		data := map[string]any{"hostname": fields["hostname"], "os_name": fields["os_name"]}
		return envelope("procfs:"+g.ProcRoot+"/sys/kernel/hostname", "gateway", "T2", name, data), nil

	case "system.status":
		p, ok := req.Typed.(*protocol.SystemStatusParams)
		if !ok {
			return nil, fail("invalid status params")
		}
		info, err := observe.ReadSystem(g.ProcRoot, g.SysRoot, p.IncludeDisks, p.IncludeThermal)
		if err != nil {
			return nil, fail("cannot read system: %v", err)
		}
		return envelope("procfs:"+g.ProcRoot, "gateway", "T2", name, info), nil

	case "system.uptime":
		info, err := observe.ReadSystem(g.ProcRoot, g.SysRoot, false, false)
		if err != nil {
			return nil, fail("cannot read uptime: %v", err)
		}
		fields := asMap(info)
		data := map[string]any{
			"uptime_s": fields["uptime_s"], "boot_time_utc": fields["boot_time_utc"],
			"now_utc": fields["now_utc"],
		}
		return envelope("procfs:"+g.ProcRoot+"/uptime", "gateway", "T2", name, data), nil

	case "process.list":
		p, ok := req.Typed.(*protocol.ProcessListParams)
		if !ok {
			return nil, fail("invalid process params")
		}
		result, err := observe.ReadProcessList(g.ProcRoot, p.Limit, p.SortBy, p.NameFilter, p.UIDFilter, p.IncludeCmdline)
		if err != nil {
			return nil, fail("cannot list processes: %v", err)
		}
		return envelope("procfs:"+g.ProcRoot+"/<pid>/stat", "gateway", "T2", name, result), nil

	case "process.inspect":
		p, ok := req.Typed.(*protocol.ProcessInspectParams)
		if !ok {
			return nil, fail("invalid process params")
		}
		info, err := observe.ReadProcessInspect(g.ProcRoot, p.PID, p.IncludeExtras)
		if err != nil {
			return nil, fail("%v", err)
		}
		return envelope(fmt.Sprintf("procfs:%s/%d", g.ProcRoot, p.PID), "gateway", "T2", name, info), nil

	case "process.diagnose":
		p, ok := req.Typed.(*protocol.ProcessDiagnoseParams)
		if !ok {
			return nil, fail("invalid process diagnosis params")
		}
		info, err := observe.DiagnoseProcesses(g.ProcRoot, p.Limit, p.UIDFilter, p.IncludeOrphans, p.TopN)
		if err != nil {
			return nil, fail("cannot diagnose processes: %v", err)
		}
		return envelope("procfs:"+g.ProcRoot+"/<pid>/stat", "gateway", "T2", name, info), nil

	case "network.connections":
		p, ok := req.Typed.(*protocol.NetworkConnectionsParams)
		if !ok {
			return nil, fail("invalid network params")
		}
		result, err := observe.ReadNetwork(g.ProcRoot, p.Limit, p.IncludeUnix, p.AttributePIDs, p.ListeningOnly, p.States)
		if err != nil {
			return nil, fail("cannot read network: %v", err)
		}
		return envelope("procfs:"+g.ProcRoot+"/net", "gateway", "T2", name, result), nil

	case "network.status":
		p, ok := req.Typed.(*protocol.NetworkStatusParams)
		if !ok {
			return nil, fail("invalid network status params")
		}
		result, err := observe.ReadNetworkStatus(g.ProcRoot, g.SysRoot, p.IncludeWireless, p.IncludeLinkSpeed)
		if err != nil {
			return nil, fail("cannot read network status: %v", err)
		}
		return envelope("sysfs:"+g.SysRoot+"/class/net", "gateway", "T2", name, result), nil

	case "filesystem.usage":
		p, ok := req.Typed.(*protocol.FilesystemUsageParams)
		if !ok {
			return nil, fail("invalid filesystem usage params")
		}
		data, err := observe.ReadFilesystemUsage(g.ProcRoot, p.IncludePseudo)
		if err != nil {
			return nil, fail("cannot read mounts: %v", err)
		}
		return envelope("procfs:"+g.ProcRoot+"/mounts", "gateway", "T2", name, data), nil

	case "filesystem.list":
		p, ok := req.Typed.(*protocol.FilesystemListParams)
		if !ok {
			return nil, fail("invalid filesystem params")
		}
		if p.Path == nil {
			data, err := observe.ListMounts(g.ProcRoot, p.IncludePseudo)
			if err != nil {
				return nil, fail("cannot read mounts: %v", err)
			}
			return envelope("procfs:"+g.ProcRoot+"/mounts", "gateway", "T2", name, data), nil
		}
		if sensitive(*p.Path) {
			return nil, fail("path is outside the readable set: %s", *p.Path)
		}
		maxEntries := p.MaxEntries
		if maxEntries > g.MaxDirEntries {
			maxEntries = g.MaxDirEntries
		}
		entries, err := observe.ListDirectory(*p.Path, maxEntries, p.ShowHidden)
		if err != nil {
			return nil, fail("cannot list %s: %v", *p.Path, err)
		}
		data := map[string]any{"path": *p.Path, "entries": entries, "count": len(entries)}
		return envelope("directory:"+*p.Path, "gateway", "T2", name, data), nil

	case "filesystem.stat":
		p, ok := req.Typed.(*protocol.FilesystemStatParams)
		if !ok {
			return nil, fail("invalid filesystem params")
		}
		if sensitive(p.Path) {
			return nil, fail("path is outside the readable set: %s", p.Path)
		}
		meta := observe.StatPath(p.Path)
		if !meta.Exists {
			return nil, fail("path does not exist: %s", p.Path)
		}
		return envelope("stat:"+p.Path, "gateway", "T2", name, meta), nil

	case "filesystem.read":
		p, ok := req.Typed.(*protocol.FilesystemReadParams)
		if !ok {
			return nil, fail("invalid filesystem params")
		}
		if reason := observe.CheckReadable(p.Path); reason != "" {
			return nil, fail("%s", reason)
		}
		limit := p.MaxBytes
		if limit > g.MaxReadBytes {
			limit = g.MaxReadBytes
		}
		content, err := observe.ReadFileBounded(p.Path, limit)
		if err != nil {
			return nil, fail("cannot read %s: %v", p.Path, err)
		}
		data := map[string]any{
			"path": p.Path, "content": content,
			"bytes": len([]byte(content)), "truncated_at": limit,
		}
		// File bytes are hostile by construction, whoever asked for them.
		return envelope("file:"+p.Path, "external", "T4", name, data), nil

	case "filesystem.cleanup_scan":
		p, ok := req.Typed.(*protocol.FilesystemCleanupScanParams)
		if !ok {
			return nil, fail("invalid scan params")
		}
		if sensitive(p.Path) {
			return nil, fail("path is outside the readable set: %s", p.Path)
		}
		maxCandidates := p.MaxCandidates
		if maxCandidates > g.MaxDirEntries {
			maxCandidates = g.MaxDirEntries
		}
		opts := actions.ScanOptions{
			MinAgeDays: p.MinAgeDays, MinSizeBytes: p.MinSizeBytes,
			MaxCandidates: maxCandidates, IncludeHidden: p.IncludeHidden,
		}
		if g.QuarantineDir != "" {
			opts.ExcludeRoots = []string{g.QuarantineDir}
		}
		result, err := actions.ScanCandidates(p.Path, opts)
		if err != nil {
			return nil, fail("cannot scan %s: %v", p.Path, err)
		}
		return envelope("scan:"+result.Root, "gateway", "T2", name, result), nil
	}
	return nil, ActionNotPermitted{GatewayError{Message: "action " + name + " is not in the gateway whitelist"}}
}

// SensitivePrefixes are never listed, stat'ed, or read.
var SensitivePrefixes = []string{
	"/etc/shadow", "/etc/sudoers", "/etc/ssh", "/root",
	"/proc/kcore", "/dev/mem", "/dev/kmem", "/dev/port",
	"/sys/kernel/security", "/boot",
}

func sensitive(path string) bool {
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		resolved = filepath.Clean(path)
	}
	for _, prefix := range SensitivePrefixes {
		if resolved == prefix || strings.HasPrefix(resolved, strings.TrimSuffix(prefix, "/")+"/") {
			return true
		}
	}
	return false
}

func asMap(value any) map[string]any {
	raw, err := json.Marshal(value)
	if err != nil {
		return map[string]any{}
	}
	out := map[string]any{}
	if err := json.Unmarshal(raw, &out); err != nil {
		return map[string]any{}
	}
	return out
}

var _ = os.ErrNotExist
