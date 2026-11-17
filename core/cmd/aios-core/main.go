// Command aios is the operator CLI and the agent proposal path.
//
// Read commands call the gateway directly: the caller is the local operator.
// Anything shaped like a model proposal goes through `aios-core act`, which uses the
// security engine, and cleanup mutations require an exact plan hash.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"aios/internal/api"
	"aios/internal/capability"
	"aios/internal/catalog"
	"aios/internal/config"
	"aios/internal/engine"
	"aios/internal/model"
	"aios/internal/plan"
	"aios/internal/policy"
	"aios/internal/protocol"
	"aios/internal/runtime"
)

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	if len(args) == 0 {
		usage()
		return 0
	}
	settings := config.Load()
	switch args[0] {
	case "help", "-h", "--help":
		return helpCommand(args[1:])
	case "version":
		return versionCommand(args[1:])
	case "ai", "ask":
		return aiCommand(settings, args[1:])
	}
	rt, err := runtime.New(settings)
	if err != nil {
		fail(err)
		return 1
	}
	switch args[0] {
	case "status":
		return observeCommand(rt, "status", "system.status", idStatus, nil, args[1:], printStatus)
	case "cpu":
		return cpuCommand(rt, args[1:])
	case "memory":
		return memoryCommand(rt, args[1:])
	case "hostname":
		return observeCommand(rt, "hostname", "system.hostname", idHostname, nil, args[1:], printHostname)
	case "processes":
		return processesCommand(rt, args[1:])
	case "inspect":
		return inspectCommand(rt, args[1:])
	case "network":
		return networkCommand(rt, args[1:])
	case "mounts":
		return observeCommand(rt, "mounts", "filesystem.list", idMounts, map[string]any{}, args[1:], printMounts)
	case "ls":
		return lsCommand(rt, args[1:])
	case "schema":
		return schemaCommand(rt, args[1:])
	case "validate":
		return validateCommand(args[1:])
	case "act":
		return actCommand(rt, args[1:])
	case "cleanup":
		return cleanupCommand(rt, args[1:])
	case "ledger":
		return ledgerCommand(rt, args[1:])
	case "serve":
		return serveCommand(rt, settings, args[1:])
	default:
		fmt.Fprintf(os.Stderr, "error: unknown command %q\n", args[0])
		if suggestion := suggestCommand(args[0]); suggestion != "" {
			fmt.Fprintf(os.Stderr, "did you mean %q?\n", suggestion)
		}
		fmt.Fprintln(os.Stderr, "run 'aios-core help' to list commands")
		return 2
	}
}

// Action ids are stable labels for the ledger. The protocol requires 8-64
// characters, so they must stay descriptive rather than terse.
const (
	idStatus   = "cli-status"
	idCPU      = "cli-cpu-sample"
	idMemory   = "cli-memory"
	idHostname = "cli-hostname"
	idProcess  = "cli-processes"
	idInspect  = "cli-inspect"
	idNetwork  = "cli-network"
	idMounts   = "cli-mounts"
	idLS       = "cli-ls-list"
)

func fail(err error) {
	fmt.Fprintln(os.Stderr, "error:", err)
}

// --- observation -----------------------------------------------------------

func newFlags(name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	fs.Usage = func() {
		if info, ok := commandByName(name); ok {
			fmt.Fprintf(fs.Output(), "usage: %s\n\n%s\n\noptions:\n", info.usage, info.summary)
		} else {
			fmt.Fprintf(fs.Output(), "usage: aios %s [options]\n\noptions:\n", name)
		}
		fs.PrintDefaults()
	}
	return fs
}

func parse(fs *flag.FlagSet, args []string) error {
	return fs.Parse(reorderArgs(fs, args))
}

// parseCode maps a flag parse failure to an exit code. -h is a success.
func parseCode(err error) int {
	if errors.Is(err, flag.ErrHelp) {
		return 0
	}
	return 2
}

// reorderArgs moves flags ahead of positionals so "cmd PATH --json" works the
// way the Python CLI allowed. Go's flag package otherwise stops at PATH.
func reorderArgs(fs *flag.FlagSet, args []string) []string {
	flags := []string{}
	positionals := []string{}
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			positionals = append(positionals, args[i+1:]...)
			break
		}
		if !strings.HasPrefix(arg, "-") || arg == "-" {
			positionals = append(positionals, arg)
			continue
		}
		flags = append(flags, arg)
		if strings.Contains(arg, "=") {
			continue
		}
		name := strings.TrimLeft(arg, "-")
		defined := fs.Lookup(name)
		if defined == nil {
			continue
		}
		if boolean, ok := defined.Value.(interface{ IsBoolFlag() bool }); ok && boolean.IsBoolFlag() {
			continue
		}
		if i+1 < len(args) {
			i++
			flags = append(flags, args[i])
		}
	}
	return append(flags, positionals...)
}

func jsonMode(fs *flag.FlagSet) *bool {
	return fs.Bool("json", false, "print JSON")
}

func observe(rt *runtime.Runtime, action, actionID string, params map[string]any) (*observationResult, error) {
	req, err := protocol.NewRequest(action, params,
		protocol.WithActionID(actionID), protocol.WithAgent("local-agent"),
		protocol.WithSession("cli"))
	if err != nil {
		return nil, err
	}
	observation, err := rt.Gateway.Execute(req)
	if err != nil {
		return nil, err
	}
	return &observationResult{
		ActionID: req.ActionID, Source: observation.Source,
		TrustDomain: observation.TrustDomain, Timestamp: observation.Timestamp,
		Data: observation.Data,
	}, nil
}

type observationResult struct {
	ActionID    string          `json:"action_id"`
	State       string          `json:"state"`
	Success     bool            `json:"success"`
	Source      string          `json:"source"`
	TrustDomain string          `json:"trust_domain"`
	Timestamp   model.Timestamp `json:"timestamp"`
	DurationMS  float64         `json:"duration_ms"`
	Data        any             `json:"data"`
}

func observeCommand(rt *runtime.Runtime, command, action, actionID string, params map[string]any, args []string, human func(any)) int {
	fs := newFlags(command)
	asJSON := jsonMode(fs)
	if err := parse(fs, args); err != nil {
		return parseCode(err)
	}
	started := time.Now()
	result, err := observe(rt, action, actionID, params)
	if err != nil {
		fail(err)
		return 1
	}
	result.State = "EXECUTED"
	result.Success = true
	result.DurationMS = float64(time.Since(started)) / float64(time.Millisecond)
	if *asJSON || human == nil {
		printJSON(result.Data)
		return 0
	}
	human(result.Data)
	return 0
}

func printStatus(data any) {
	fields := asMap(data)
	fmt.Printf("hostname:    %v\n", valueOr(fields["hostname"], "-"))
	fmt.Printf("kernel:      %v\n", valueOr(fields["kernel"], "-"))
	fmt.Printf("uptime:      %vs\n", valueOr(fields["uptime_s"], "-"))
	fmt.Printf("load 1/5/15: %s\n", formatLoads(fields))
	fmt.Printf("processes:   %v\n", valueOr(fields["processes_total"], "-"))
	fmt.Printf("cores:       %v\n", valueOr(fields["logical_cores"], "-"))
}

func formatLoads(fields map[string]any) string {
	loads := make([]string, 0, 3)
	missing := false
	for _, key := range []string{"load_average_1m", "load_average_5m", "load_average_15m"} {
		value, ok := fields[key].(float64)
		if !ok {
			missing = true
			break
		}
		loads = append(loads, fmt.Sprintf("%.2f", value))
	}
	if missing {
		return "-"
	}
	return strings.Join(loads, " ")
}

func printHostname(data any) {
	fields := asMap(data)
	fmt.Printf("%v\n", valueOr(fields["hostname"], "-"))
}

func printMounts(data any) {
	fields := asMap(data)
	mounts, _ := fields["mounts"].([]any)
	fmt.Printf("%-24s %-10s %10s %10s %6s %10s\n", "MOUNT", "FS", "SIZE", "USED", "USE%", "FREE")
	for _, row := range mounts {
		mount, _ := row.(map[string]any)
		percent := "-"
		if value, ok := mount["used_percent"].(float64); ok {
			percent = fmt.Sprintf("%.0f%%", value)
		}
		fmt.Printf("%-24.24v %-10v %10s %10s %6s %10s\n",
			valueOr(mount["mount_point"], "-"), valueOr(mount["fs_type"], "-"),
			humanBytes(int64(number(mount["total_bytes"]))),
			humanBytes(int64(number(mount["used_bytes"]))), percent,
			humanBytes(int64(number(mount["free_bytes"]))))
	}
}

func cpuCommand(rt *runtime.Runtime, args []string) int {
	fs := newFlags("cpu")
	interval := fs.Float64("interval", 0.25, "sample interval in seconds")
	watch := fs.Bool("watch", false, "refresh until interrupted")
	fs.BoolVar(watch, "w", false, "alias for --watch")
	asJSON := jsonMode(fs)
	if err := parse(fs, args); err != nil {
		return parseCode(err)
	}
	for {
		result, err := observe(rt, "system.cpu", idCPU, map[string]any{"interval_s": *interval})
		if err != nil {
			fail(err)
			return 1
		}
		if *asJSON {
			printJSON(result.Data)
			return 0
		}
		printCPU(result.Data)
		if !*watch {
			return 0
		}
		time.Sleep(time.Second)
		clearScreen()
	}
}

func printCPU(data any) {
	fields := asMap(data)
	if percent, ok := fields["percent"].(map[string]any); ok {
		fmt.Printf("total: %.1f%%  user: %.1f%%  system: %.1f%%  idle: %.1f%%\n",
			number(percent["total"]), number(percent["user"]),
			number(percent["system"]), number(percent["idle"]))
		return
	}
	printJSON(data)
}

func memoryCommand(rt *runtime.Runtime, args []string) int {
	fs := newFlags("memory")
	watch := fs.Bool("watch", false, "refresh until interrupted")
	fs.BoolVar(watch, "w", false, "alias for --watch")
	asJSON := jsonMode(fs)
	if err := parse(fs, args); err != nil {
		return parseCode(err)
	}
	for {
		result, err := observe(rt, "system.memory", idMemory, nil)
		if err != nil {
			fail(err)
			return 1
		}
		if *asJSON {
			printJSON(result.Data)
			return 0
		}
		printMemory(result.Data)
		if !*watch {
			return 0
		}
		time.Sleep(2 * time.Second)
		clearScreen()
	}
}

func printMemory(data any) {
	fields := asMap(data)
	fmt.Printf("used:  %.1f%%\n", number(fields["used_percent"]))
	fmt.Printf("total: %s\n", humanBytes(int64(number(fields["total_kb"]))*1024))
	fmt.Printf("avail: %s\n", humanBytes(int64(number(fields["available_kb"]))*1024))
}

// clearScreen refreshes only when writing to a terminal, so piped output keeps
// every sample instead of erasing earlier lines.
func clearScreen() {
	info, err := os.Stdout.Stat()
	if err == nil && info.Mode()&os.ModeCharDevice != 0 {
		fmt.Print("\033[H\033[2J")
	}
}

func processesCommand(rt *runtime.Runtime, args []string) int {
	fs := newFlags("processes")
	limit := fs.Int("limit", 50, "maximum processes")
	sortBy := fs.String("sort", "cpu", "cpu, memory, pid, or name")
	name := fs.String("name", "", "name filter")
	asJSON := jsonMode(fs)
	if err := parse(fs, args); err != nil {
		return parseCode(err)
	}
	params := map[string]any{"limit": *limit, "sort_by": *sortBy}
	if *name != "" {
		params["name_filter"] = *name
	}
	result, err := observe(rt, "process.list", idProcess, params)
	if err != nil {
		fail(err)
		return 1
	}
	if *asJSON {
		printJSON(result.Data)
		return 0
	}
	fields := asMap(result.Data)
	rows, _ := fields["processes"].([]any)
	fmt.Printf("%7s %-20s %6s %10s\n", "PID", "NAME", "STATE", "RSS")
	for _, row := range rows {
		process, _ := row.(map[string]any)
		fmt.Printf("%7v %-20.20s %6v %10s\n", process["pid"], process["name"],
			process["state"], humanBytes(int64(number(process["rss_bytes"]))))
	}
	return 0
}

func inspectCommand(rt *runtime.Runtime, args []string) int {
	fs := newFlags("inspect")
	asJSON := jsonMode(fs)
	if err := parse(fs, args); err != nil {
		return parseCode(err)
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "usage: aios-core inspect PID [--json]")
		return 2
	}
	var pid int
	if _, err := fmt.Sscanf(fs.Arg(0), "%d", &pid); err != nil {
		fail(err)
		return 2
	}
	result, err := observe(rt, "process.inspect", idInspect, map[string]any{"pid": pid})
	if err != nil {
		fail(err)
		return 1
	}
	if *asJSON {
		printJSON(result.Data)
		return 0
	}
	fields := asMap(result.Data)
	fmt.Printf("pid:         %v\nname:        %v\nstate:       %v\nuid:         %v\nrss:         %s\ncmdline:     %v\n",
		fields["pid"], fields["name"], fields["state"], fields["uid"],
		humanBytes(int64(number(fields["rss_bytes"]))), fields["cmdline"])
	return 0
}

func networkCommand(rt *runtime.Runtime, args []string) int {
	fs := newFlags("network")
	limit := fs.Int("limit", 200, "maximum connections")
	listening := fs.Bool("listening", false, "listening sockets only")
	asJSON := jsonMode(fs)
	if err := parse(fs, args); err != nil {
		return parseCode(err)
	}
	result, err := observe(rt, "network.connections", idNetwork, map[string]any{
		"limit": *limit, "listening_only": *listening, "attribute_pids": true,
	})
	if err != nil {
		fail(err)
		return 1
	}
	if *asJSON {
		printJSON(result.Data)
		return 0
	}
	fields := asMap(result.Data)
	rows, _ := fields["connections"].([]any)
	fmt.Printf("%-6s %-24s %-24s %s\n", "PROTO", "LOCAL", "REMOTE", "STATE")
	for _, row := range rows {
		connection, _ := row.(map[string]any)
		fmt.Printf("%-6s %-24s %-24s %v\n", transport(connection["family"]),
			address(connection["local_address"], connection["local_port"]),
			address(connection["remote_address"], connection["remote_port"]),
			valueOr(connection["state"], "-"))
	}
	return 0
}

func lsCommand(rt *runtime.Runtime, args []string) int {
	fs := newFlags("ls")
	all := fs.Bool("all", false, "include hidden entries")
	max := fs.Int("max", 500, "maximum entries")
	asJSON := jsonMode(fs)
	if err := parse(fs, args); err != nil {
		return parseCode(err)
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "usage: aios-core ls PATH [--all] [--max N] [--json]")
		return 2
	}
	result, err := observe(rt, "filesystem.list", idLS, map[string]any{
		"path": fs.Arg(0), "show_hidden": *all, "max_entries": *max,
	})
	if err != nil {
		fail(err)
		return 1
	}
	if *asJSON {
		printJSON(result.Data)
		return 0
	}
	fields := asMap(result.Data)
	entries, _ := fields["entries"].([]any)
	fmt.Printf("%-11s %10s %-19s %s\n", "MODE", "SIZE", "MODIFIED", "PATH")
	for _, row := range entries {
		entry, _ := row.(map[string]any)
		modified := valueOr(entry["modified_utc"], "-")
		if text, ok := modified.(string); ok && len(text) > 19 {
			modified = text[:19]
		}
		fmt.Printf("%-11v %10s %-19v %v\n", valueOr(entry["mode"], "-"),
			humanBytes(int64(number(entry["size_bytes"]))), modified, entry["path"])
	}
	return 0
}

func schemaCommand(rt *runtime.Runtime, args []string) int {
	fs := newFlags("schema")
	asJSON := jsonMode(fs)
	if err := parse(fs, args); err != nil {
		return parseCode(err)
	}
	allowed := make([]string, 0, len(catalogNames()))
	for _, name := range catalogNames() {
		allowed = append(allowed, name)
	}
	sort.Strings(allowed)
	payload := map[string]any{"protocol_version": api.Version, "allowed_actions": allowed}
	if *asJSON {
		printJSON(payload)
		return 0
	}
	fmt.Printf("%-26s %-10s %-7s %-9s %s\n", "ACTION", "EFFECT", "RISK", "APPROVAL", "READ-ONLY")
	for _, name := range allowed {
		descriptor := catalog.Catalog[name]
		readOnly := "no"
		if descriptor.ReadOnly {
			readOnly = "yes"
		}
		fmt.Printf("%-26s %-10s %-7s %-9s %s\n", name, descriptor.Effect,
			descriptor.Risk, descriptor.Approval, readOnly)
	}
	return 0
}

func validateCommand(args []string) int {
	fs := newFlags("validate")
	asJSON := jsonMode(fs)
	if err := parse(fs, args); err != nil {
		return parseCode(err)
	}
	if fs.NArg() > 1 {
		fmt.Fprintln(os.Stderr, "usage: aios-core validate [FILE] [--json]")
		return 2
	}
	raw, err := readPayload(fs.Arg(0))
	if err != nil {
		fail(err)
		return 1
	}
	req, err := protocol.ParseRequest(raw)
	if err != nil {
		if *asJSON {
			printJSON(map[string]any{"valid": false, "state": "DENIED", "error": err.Error()})
		} else {
			fmt.Println("DENIED:", err)
		}
		return 1
	}
	body := map[string]any{
		"valid": true, "action_id": req.ActionID, "type": req.ActionName(),
		"validated_params": asMap(req.Typed), "trust_domain": string(req.Trust),
		"state": "VALIDATED",
	}
	if *asJSON {
		printJSON(body)
	} else {
		fmt.Printf("VALID %s (%s)\n", req.ActionName(), req.Trust)
	}
	return 0
}

func actCommand(rt *runtime.Runtime, args []string) int {
	fs := newFlags("act")
	dryRun := fs.Bool("dry-run", false, "authorize without executing")
	asJSON := jsonMode(fs)
	if err := parse(fs, args); err != nil {
		return parseCode(err)
	}
	if fs.NArg() > 1 {
		fmt.Fprintln(os.Stderr, "usage: aios-core act [FILE] [--dry-run] [--json]")
		return 2
	}
	raw, err := readPayload(fs.Arg(0))
	if err != nil {
		fail(err)
		return 1
	}
	req, err := protocol.ParseRequest(raw)
	if err != nil {
		fail(err)
		return 1
	}
	var verdict engine.Verdict
	if *dryRun {
		verdict = rt.Engine.Authorize(req, nil, nil)
	} else {
		verdict = rt.Engine.Process(req, nil, nil)
	}
	if *asJSON {
		printJSON(verdict)
	} else {
		fmt.Printf("%s %s (%s)\n", verdict.Decision, verdict.Reason, verdict.State)
	}
	if verdict.Decision == policy.Deny {
		return 1
	}
	return 0
}

// --- cleanup ---------------------------------------------------------------

func cleanupCommand(rt *runtime.Runtime, args []string) int {
	if len(args) == 0 {
		helpCommand([]string{"cleanup"})
		return 2
	}
	switch args[0] {
	case "scan":
		return cleanupScan(rt, args[1:])
	case "quarantine":
		return cleanupQuarantine(rt, args[1:])
	case "restore":
		return cleanupRestore(rt, args[1:])
	case "help", "-h", "--help":
		return helpCommand([]string{"cleanup"})
	default:
		fmt.Fprintf(os.Stderr, "error: unknown cleanup command %q\n", args[0])
		if suggestion := suggestCommand("cleanup " + args[0]); suggestion != "" {
			fmt.Fprintf(os.Stderr, "did you mean %q?\n", suggestion)
		}
		return 2
	}
}

func cleanupScan(rt *runtime.Runtime, args []string) int {
	fs := newFlags("cleanup scan")
	minAge := fs.Int("min-age-days", 30, "only files older than this")
	minSize := fs.Int64("min-size", 0, "only files at least this large")
	maxCandidates := fs.Int("max-candidates", 500, "hard candidate cap")
	includeHidden := fs.Bool("include-hidden", false, "include dotfiles")
	planOut := fs.String("plan-out", "", "write the plan JSON here")
	asJSON := jsonMode(fs)
	if err := parse(fs, args); err != nil {
		return parseCode(err)
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "usage: aios-core cleanup scan PATH [options]")
		return 2
	}
	root, err := absolutePath(fs.Arg(0))
	if err != nil {
		fail(err)
		return 1
	}

	manager := capability.EmptyManager()
	manager.Grant("local-agent", capability.Capability{
		Action: "filesystem.cleanup_scan", Scope: []string{root},
		GrantedBy: "operator-cli", Reason: "interactive cleanup scan",
	})
	rt = rt.WithCapabilities(manager)

	req, err := protocol.NewRequest("filesystem.cleanup_scan", map[string]any{
		"path": root, "min_age_days": *minAge, "min_size_bytes": *minSize,
		"max_candidates": *maxCandidates, "include_hidden": *includeHidden,
	}, protocol.WithActionID("cli-cleanup-scan"), protocol.WithSession("cli"),
		protocol.WithIntent("scan "+root+" for cleanup candidates"))
	if err != nil {
		fail(err)
		return 1
	}
	verdict := rt.Engine.Process(req, nil, nil)
	if verdict.Decision != policy.Allow || verdict.Observation == nil {
		reason := verdict.Reason
		if verdict.DenialReason != nil {
			reason = string(*verdict.DenialReason)
		}
		fmt.Fprintln(os.Stderr, "DENIED", reason)
		return 1
	}
	scan, ok := verdict.Observation.Data.(model.ScanResult)
	if !ok {
		fail(fmt.Errorf("unexpected scan payload %T", verdict.Observation.Data))
		return 1
	}
	p := plan.FromCandidates(scan.Candidates, scan.Root, "local-agent", "cli",
		stringPtr("cleanup candidates under "+scan.Root), maxInt(*maxCandidates, 1),
		10_737_418_240, time.Now())
	if *planOut != "" {
		encoded, _ := json.MarshalIndent(p, "", "  ")
		if err := os.WriteFile(*planOut, append(encoded, '\n'), 0o600); err != nil {
			fail(err)
			return 1
		}
	}
	if *asJSON {
		printJSON(map[string]any{"scan": scan, "plan": p})
		return 0
	}
	fmt.Printf("scan %s\n", scan.Root)
	fmt.Printf("  candidates: %d\n  bytes:      %d\n  skipped:    %d\n", scan.Total, scan.TotalBytes, scan.Skipped)
	fmt.Printf("  plan:       %s\n  hash:       %s\n", p.PlanID, p.PlanHash)
	if *planOut != "" {
		fmt.Printf("  plan file:  %s\n", *planOut)
	} else {
		fmt.Println("  use --plan-out FILE to write the plan for approval")
	}
	for i, candidate := range scan.Candidates {
		if i >= 20 {
			fmt.Printf("... %d more\n", scan.Total-20)
			break
		}
		fmt.Printf("  %s %10d %s\n", candidate.CandidateID, candidate.SizeBytes, candidate.Path)
	}
	return 0
}

func cleanupQuarantine(rt *runtime.Runtime, args []string) int {
	fs := newFlags("cleanup quarantine")
	confirm := fs.String("confirm-plan-hash", "", "exact plan hash being approved")
	asJSON := jsonMode(fs)
	if err := parse(fs, args); err != nil {
		return parseCode(err)
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "usage: aios-core cleanup quarantine PLAN --confirm-plan-hash HASH")
		return 2
	}
	p, err := loadPlan(fs.Arg(0))
	if err != nil {
		fail(err)
		return 1
	}
	if *confirm != p.PlanHash {
		fmt.Fprintln(os.Stderr, "DENIED plan hash does not match; nothing was moved")
		return 1
	}
	if len(p.Steps) == 0 {
		fmt.Println("empty plan; nothing to do")
		return 0
	}
	grant, err := approve(rt, p)
	if err != nil {
		fail(err)
		return 1
	}

	manager := capability.EmptyManager()
	paths := make([]string, 0, len(p.Steps))
	for _, step := range p.Steps {
		paths = append(paths, step.Path)
	}
	manager.Grant("local-agent", capability.Capability{
		Action: "filesystem.quarantine", Scope: paths,
		GrantedBy: "operator-cli", Reason: "approved plan " + p.PlanID,
	})
	rollbackPaths := make([]string, 0, len(p.Rollback))
	for _, step := range p.Rollback {
		rollbackPaths = append(rollbackPaths, step.Path)
	}
	manager.Grant("local-agent", capability.Capability{
		Action: "filesystem.restore", Scope: rollbackPaths,
		GrantedBy: "operator-cli", Reason: "rollback for plan " + p.PlanID,
	})
	rt = rt.WithCapabilities(manager)

	records := []map[string]any{}
	completed := []plan.Step{}
	var failed map[string]any
	for _, step := range p.Steps {
		req, err := protocol.NewRequest("filesystem.quarantine", map[string]any{
			"path": step.Path, "plan_id": p.PlanID, "candidate_id": step.CandidateID,
		}, protocol.WithActionID("cli-quarantine-"+step.CandidateID[2:]),
			protocol.WithSession("cli"), protocol.WithIntentValue(p.Intent))
		if err != nil {
			fail(err)
			return 1
		}
		verdict := rt.Engine.Process(req, &p, &grant)
		records = append(records, recordOf(step, verdict))
		if verdict.Decision == policy.Allow && verdict.Executed {
			completed = append(completed, step)
			continue
		}
		failed = records[len(records)-1]
		break
	}

	rollback := []map[string]any{}
	if failed != nil && len(completed) > 0 {
		for i := len(completed) - 1; i >= 0; i-- {
			step := completed[i]
			req, err := protocol.NewRequest("filesystem.restore", map[string]any{
				"path": step.Path, "plan_id": p.PlanID, "candidate_id": step.CandidateID,
			}, protocol.WithActionID("cli-rollback-"+step.CandidateID[2:]),
				protocol.WithSession("cli"))
			if err != nil {
				continue
			}
			verdict := rt.Engine.Process(req, &p, &grant)
			rollback = append(rollback, map[string]any{
				"candidate_id": step.CandidateID, "decision": verdict.Decision,
				"reason": verdict.Reason,
			})
		}
	}
	payload := map[string]any{
		"plan_id": p.PlanID, "plan_hash": p.PlanHash, "steps": records,
		"rollback": rollback, "applied": len(completed), "failed": failed,
	}
	if failed != nil {
		payload["applied"] = 0
	}
	if *asJSON {
		printJSON(payload)
	} else {
		fmt.Printf("plan %s\n", p.PlanID)
		for _, record := range records {
			fmt.Printf("  %-5v %v\n", record["decision"], record["path"])
		}
	}
	if failed != nil {
		return 1
	}
	return 0
}

func cleanupRestore(rt *runtime.Runtime, args []string) int {
	fs := newFlags("cleanup restore")
	confirm := fs.String("confirm-plan-hash", "", "exact plan hash being approved")
	candidate := fs.String("candidate", "", "restore only this candidate id")
	asJSON := jsonMode(fs)
	if err := parse(fs, args); err != nil {
		return parseCode(err)
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "usage: aios-core cleanup restore PLAN --confirm-plan-hash HASH [--candidate ID]")
		return 2
	}
	p, err := loadPlan(fs.Arg(0))
	if err != nil {
		fail(err)
		return 1
	}
	if *confirm != p.PlanHash {
		fmt.Fprintln(os.Stderr, "DENIED plan hash does not match; nothing was restored")
		return 1
	}
	steps := []plan.RollbackStep{}
	for _, step := range p.Rollback {
		if *candidate == "" || step.CandidateID == *candidate {
			steps = append(steps, step)
		}
	}
	if len(steps) == 0 {
		fmt.Println("no matching restore steps")
		return 0
	}
	grant, err := approve(rt, p)
	if err != nil {
		fail(err)
		return 1
	}
	manager := capability.EmptyManager()
	paths := make([]string, 0, len(steps))
	for _, step := range steps {
		paths = append(paths, step.Path)
	}
	manager.Grant("local-agent", capability.Capability{
		Action: "filesystem.restore", Scope: paths,
		GrantedBy: "operator-cli", Reason: "approved restore for " + p.PlanID,
	})
	rt = rt.WithCapabilities(manager)

	records := []map[string]any{}
	allowed := true
	for _, step := range steps {
		req, err := protocol.NewRequest("filesystem.restore", map[string]any{
			"path": step.Path, "plan_id": p.PlanID, "candidate_id": step.CandidateID,
		}, protocol.WithActionID("cli-restore-"+step.CandidateID[2:]),
			protocol.WithSession("cli"))
		if err != nil {
			fail(err)
			return 1
		}
		verdict := rt.Engine.Process(req, &p, &grant)
		records = append(records, recordOfRollback(step, verdict))
		if verdict.Decision != policy.Allow {
			allowed = false
		}
	}
	if *asJSON {
		printJSON(map[string]any{"plan_id": p.PlanID, "steps": records})
	} else {
		for _, record := range records {
			fmt.Printf("  %-5v %v\n", record["decision"], record["path"])
		}
	}
	if !allowed {
		return 1
	}
	return 0
}

func approve(rt *runtime.Runtime, p plan.Plan) (plan.Grant, error) {
	authority, err := rt.Authority()
	if err != nil {
		return plan.Grant{}, err
	}
	token, err := authority.Mint(p, fmt.Sprintf("uid:%d", os.Getuid()), 0)
	if err != nil {
		return plan.Grant{}, err
	}
	return authority.Verify(token, p, true, time.Now())
}

func loadPlan(path string) (plan.Plan, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return plan.Plan{}, err
	}
	var p plan.Plan
	if err := model.DecodeStrict(raw, &p); err != nil {
		return plan.Plan{}, err
	}
	if err := p.Validate(); err != nil {
		return plan.Plan{}, err
	}
	return p, nil
}

func recordOf(step plan.Step, verdict engine.Verdict) map[string]any {
	record := map[string]any{
		"candidate_id": step.CandidateID, "path": step.Path,
		"decision": verdict.Decision, "state": verdict.State,
		"reason": verdict.Reason, "denial_reason": verdict.DenialReason,
	}
	if verdict.Result != nil {
		record["result"] = verdict.Result.Data
	}
	return record
}

func recordOfRollback(step plan.RollbackStep, verdict engine.Verdict) map[string]any {
	return map[string]any{
		"candidate_id": step.CandidateID, "path": step.Path,
		"decision": verdict.Decision, "state": verdict.State,
		"reason": verdict.Reason, "denial_reason": verdict.DenialReason,
	}
}

func ledgerCommand(rt *runtime.Runtime, args []string) int {
	fs := newFlags("ledger")
	action := fs.String("action", "", "only this action id")
	asJSON := jsonMode(fs)
	if err := parse(fs, args); err != nil {
		return parseCode(err)
	}
	entries := rt.Ledger.Entries()
	if *action != "" {
		entries = rt.Ledger.ByAction(*action)
	}
	if *asJSON {
		printJSON(entries)
		return 0
	}
	if len(entries) == 0 {
		fmt.Println("ledger is empty")
		return 0
	}
	for _, entry := range entries {
		fmt.Printf("%s %-10s %-22s %s\n", model.FormatTime(entry.At.Time),
			entry.State, entry.Action, entry.Decision)
	}
	return 0
}

func serveCommand(rt *runtime.Runtime, settings config.Settings, args []string) int {
	fs := newFlags("serve")
	host := fs.String("host", settings.APIHost, "bind address")
	port := fs.Int("port", settings.APIPort, "bind port")
	if err := parse(fs, args); err != nil {
		return parseCode(err)
	}
	settings.APIHost = *host
	settings.APIPort = *port
	fmt.Printf("AIOS control API listening on %s:%d\n", settings.APIHost, settings.APIPort)
	if err := api.New(rt).ListenAndServe(settings); err != nil {
		fail(err)
		return 1
	}
	return 0
}

// --- helpers ---------------------------------------------------------------

func readPayload(path string) ([]byte, error) {
	if path == "" || path == "-" {
		if stdinIsTerminal() {
			return nil, errors.New(
				"no proposal file given and stdin is a terminal; pass a FILE or pipe JSON",
			)
		}
		return io.ReadAll(os.Stdin)
	}
	return os.ReadFile(path)
}

func absolutePath(path string) (string, error) {
	if strings.HasPrefix(path, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		path = home + path[1:]
	}
	return filepath.Abs(path)
}

func printJSON(value any) {
	encoded, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		fail(err)
		return
	}
	fmt.Println(string(encoded))
}

func asMap(value any) map[string]any {
	encoded, err := json.Marshal(value)
	if err != nil {
		return map[string]any{}
	}
	out := map[string]any{}
	if err := json.Unmarshal(encoded, &out); err != nil {
		return map[string]any{}
	}
	return out
}

func number(value any) float64 {
	switch typed := value.(type) {
	case float64:
		return typed
	case int:
		return float64(typed)
	case int64:
		return float64(typed)
	case json.Number:
		parsed, _ := typed.Float64()
		return parsed
	default:
		return 0
	}
}

func humanBytes(value int64) string {
	if value <= 0 {
		return "-"
	}
	units := []string{"B", "KiB", "MiB", "GiB", "TiB"}
	size := float64(value)
	index := 0
	for size >= 1024 && index < len(units)-1 {
		size /= 1024
		index++
	}
	return fmt.Sprintf("%.1f%s", size, units[index])
}

func address(host, port any) string {
	if host == nil || host == "" {
		return "-"
	}
	return fmt.Sprintf("%v:%v", host, port)
}

// transport turns a socket family such as tcp6 into its protocol label.
func transport(family any) string {
	value, ok := family.(string)
	if !ok || value == "" {
		return "-"
	}
	return strings.ToUpper(strings.TrimSuffix(value, "6"))
}

func valueOr(value any, fallback string) any {
	if value == nil {
		return fallback
	}
	return value
}

func stringPtr(value string) *string { return &value }

func catalogNames() []string {
	names := make([]string, 0, len(catalog.Catalog))
	for name := range catalog.Catalog {
		names = append(names, name)
	}
	return names
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
