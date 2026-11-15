package protocol

import (
	"bytes"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
)

// SystemCPUParams controls one CPU sample.
type SystemCPUParams struct {
	IntervalS          float64 `json:"interval_s"`
	IncludeFrequencies bool    `json:"include_frequencies"`
}

func (*SystemCPUParams) actionParams() {}

// SystemMemoryParams controls the memory view.
type SystemMemoryParams struct {
	IncludeSwap   bool `json:"include_swap"`
	IncludeFields bool `json:"include_fields"`
}

func (*SystemMemoryParams) actionParams() {}

// SystemHostnameParams takes no options.
type SystemHostnameParams struct{}

func (*SystemHostnameParams) actionParams() {}

// SystemStatusParams controls the system summary.
type SystemStatusParams struct {
	IncludeDisks   bool `json:"include_disks"`
	IncludeThermal bool `json:"include_thermal"`
}

func (*SystemStatusParams) actionParams() {}

// SystemUptimeParams takes no options.
type SystemUptimeParams struct{}

func (*SystemUptimeParams) actionParams() {}

// ProcessListParams controls process enumeration.
type ProcessListParams struct {
	Limit          int     `json:"limit"`
	SortBy         string  `json:"sort_by"`
	NameFilter     *string `json:"name_filter"`
	UIDFilter      *int    `json:"uid_filter"`
	IncludeCmdline bool    `json:"include_cmdline"`
}

func (*ProcessListParams) actionParams() {}

// ProcessInspectParams selects one pid.
type ProcessInspectParams struct {
	PID           int  `json:"pid"`
	IncludeExtras bool `json:"include_extras"`
}

func (*ProcessInspectParams) actionParams() {}

// NetworkConnectionsParams controls the socket table view.
type NetworkConnectionsParams struct {
	Limit         int      `json:"limit"`
	IncludeUnix   bool     `json:"include_unix"`
	AttributePIDs bool     `json:"attribute_pids"`
	ListeningOnly bool     `json:"listening_only"`
	States        []string `json:"states"`
}

func (*NetworkConnectionsParams) actionParams() {}

// FilesystemListParams lists a directory, or mounts when Path is nil.
type FilesystemListParams struct {
	Path          *string `json:"path"`
	IncludePseudo bool    `json:"include_pseudo"`
	MaxEntries    int     `json:"max_entries"`
	ShowHidden    bool    `json:"show_hidden"`
}

func (*FilesystemListParams) actionParams() {}

// FilesystemStatParams stats one path.
type FilesystemStatParams struct {
	Path string `json:"path"`
}

func (*FilesystemStatParams) actionParams() {}

// FilesystemReadParams reads bounded file content.
type FilesystemReadParams struct {
	Path     string `json:"path"`
	MaxBytes int    `json:"max_bytes"`
}

func (*FilesystemReadParams) actionParams() {}

// FilesystemCleanupScanParams controls the read-only cleanup scan.
type FilesystemCleanupScanParams struct {
	Path          string `json:"path"`
	MinAgeDays    int    `json:"min_age_days"`
	MinSizeBytes  int64  `json:"min_size_bytes"`
	MaxCandidates int    `json:"max_candidates"`
	IncludeHidden bool   `json:"include_hidden"`
}

func (*FilesystemCleanupScanParams) actionParams() {}

// PlanTargetParams is the common shape of a mutation step.
type PlanTargetParams struct {
	Path        string `json:"path"`
	PlanID      string `json:"plan_id"`
	CandidateID string `json:"candidate_id"`
}

// FilesystemQuarantineParams moves one approved candidate.
type FilesystemQuarantineParams struct {
	PlanTargetParams
}

func (*FilesystemQuarantineParams) actionParams() {}

// FilesystemRestoreParams returns one quarantined candidate.
type FilesystemRestoreParams struct {
	PlanTargetParams
}

func (*FilesystemRestoreParams) actionParams() {}

var networkStates = map[string]bool{
	"ESTABLISHED": true, "LISTEN": true, "SYN_SENT": true, "SYN_RECV": true,
	"FIN_WAIT1": true, "FIN_WAIT2": true, "TIME_WAIT": true, "CLOSE": true,
	"CLOSE_WAIT": true, "LAST_ACK": true, "CLOSING": true,
}

// ParamsFor returns a zero-value typed params object for an action.
func ParamsFor(action string) Params {
	switch action {
	case "system.cpu":
		return &SystemCPUParams{IntervalS: 0.25, IncludeFrequencies: true}
	case "system.memory":
		return &SystemMemoryParams{IncludeSwap: true}
	case "system.hostname":
		return &SystemHostnameParams{}
	case "system.status":
		return &SystemStatusParams{IncludeDisks: true, IncludeThermal: true}
	case "system.uptime":
		return &SystemUptimeParams{}
	case "process.list":
		return &ProcessListParams{Limit: 50, SortBy: "cpu"}
	case "process.inspect":
		return &ProcessInspectParams{IncludeExtras: true}
	case "network.connections":
		return &NetworkConnectionsParams{Limit: 200, AttributePIDs: true}
	case "filesystem.list":
		return &FilesystemListParams{MaxEntries: 500}
	case "filesystem.stat":
		return &FilesystemStatParams{}
	case "filesystem.read":
		return &FilesystemReadParams{MaxBytes: 65_536}
	case "filesystem.cleanup_scan":
		return &FilesystemCleanupScanParams{MinAgeDays: 30, MaxCandidates: 500}
	case "filesystem.quarantine":
		return &FilesystemQuarantineParams{}
	case "filesystem.restore":
		return &FilesystemRestoreParams{}
	default:
		return nil
	}
}

func validateParams(action string, raw map[string]json.RawMessage) (Params, map[string]any, error) {
	if raw == nil {
		raw = map[string]json.RawMessage{}
	}
	typed := ParamsFor(action)
	if typed == nil {
		return nil, nil, fmt.Errorf("unknown action %s", action)
	}

	switch p := typed.(type) {
	case *SystemCPUParams:
		if err := decodeStrict(raw, p, "interval_s", "include_frequencies"); err != nil {
			return nil, nil, err
		}
		if p.IntervalS < 0 || p.IntervalS > 5 {
			return nil, nil, fmt.Errorf("interval_s must be between 0 and 5")
		}
	case *SystemMemoryParams:
		if err := decodeStrict(raw, p, "include_swap", "include_fields"); err != nil {
			return nil, nil, err
		}
	case *SystemHostnameParams:
		if err := decodeStrict(raw, p); err != nil {
			return nil, nil, err
		}
	case *SystemStatusParams:
		if err := decodeStrict(raw, p, "include_disks", "include_thermal"); err != nil {
			return nil, nil, err
		}
	case *SystemUptimeParams:
		if err := decodeStrict(raw, p); err != nil {
			return nil, nil, err
		}
	case *ProcessListParams:
		if err := decodeStrict(raw, p, "limit", "sort_by", "name_filter", "uid_filter", "include_cmdline"); err != nil {
			return nil, nil, err
		}
		if p.Limit < 1 || p.Limit > 1000 {
			return nil, nil, fmt.Errorf("limit must be between 1 and 1000")
		}
		if !slices.Contains([]string{"cpu", "memory", "pid", "name"}, p.SortBy) {
			return nil, nil, fmt.Errorf("sort_by must be one of cpu, memory, pid, name")
		}
		if p.UIDFilter != nil && *p.UIDFilter < 0 {
			return nil, nil, fmt.Errorf("uid_filter must be non-negative")
		}
		if p.NameFilter != nil {
			if len(*p.NameFilter) > 64 {
				return nil, nil, fmt.Errorf("name_filter is too long")
			}
			for _, r := range *p.NameFilter {
				if r < 0x20 || r == 0x7f {
					return nil, nil, fmt.Errorf("name_filter must not contain control characters")
				}
			}
		}
	case *ProcessInspectParams:
		if err := decodeStrict(raw, p, "pid", "include_extras"); err != nil {
			return nil, nil, err
		}
		if p.PID < 1 || p.PID > 4_194_303 {
			return nil, nil, fmt.Errorf("pid must be between 1 and 4194303")
		}
	case *NetworkConnectionsParams:
		if err := decodeStrict(raw, p, "limit", "include_unix", "attribute_pids", "listening_only", "states"); err != nil {
			return nil, nil, err
		}
		if p.Limit < 1 || p.Limit > 2000 {
			return nil, nil, fmt.Errorf("limit must be between 1 and 2000")
		}
		seen := map[string]bool{}
		deduped := make([]string, 0, len(p.States))
		for _, state := range p.States {
			if !networkStates[state] {
				return nil, nil, fmt.Errorf("unknown connection state %q", state)
			}
			if !seen[state] {
				seen[state] = true
				deduped = append(deduped, state)
			}
		}
		p.States = deduped
	case *FilesystemListParams:
		if err := decodeStrict(raw, p, "path", "include_pseudo", "max_entries", "show_hidden"); err != nil {
			return nil, nil, err
		}
		if p.Path != nil {
			if err := ValidPath(*p.Path); err != nil {
				return nil, nil, err
			}
		}
		if p.MaxEntries < 1 || p.MaxEntries > 5000 {
			return nil, nil, fmt.Errorf("max_entries must be between 1 and 5000")
		}
	case *FilesystemStatParams:
		if err := decodeStrict(raw, p, "path"); err != nil {
			return nil, nil, err
		}
		if err := ValidPath(p.Path); err != nil {
			return nil, nil, err
		}
	case *FilesystemReadParams:
		if err := decodeStrict(raw, p, "path", "max_bytes"); err != nil {
			return nil, nil, err
		}
		if err := ValidPath(p.Path); err != nil {
			return nil, nil, err
		}
		if p.MaxBytes < 1 || p.MaxBytes > 1_048_576 {
			return nil, nil, fmt.Errorf("max_bytes must be between 1 and 1048576")
		}
	case *FilesystemCleanupScanParams:
		if err := decodeStrict(raw, p, "path", "min_age_days", "min_size_bytes", "max_candidates", "include_hidden"); err != nil {
			return nil, nil, err
		}
		if err := ValidPath(p.Path); err != nil {
			return nil, nil, err
		}
		if p.MinAgeDays < 0 || p.MinAgeDays > 3650 {
			return nil, nil, fmt.Errorf("min_age_days must be between 0 and 3650")
		}
		if p.MinSizeBytes < 0 {
			return nil, nil, fmt.Errorf("min_size_bytes must be non-negative")
		}
		if p.MaxCandidates < 1 || p.MaxCandidates > 5000 {
			return nil, nil, fmt.Errorf("max_candidates must be between 1 and 5000")
		}
	case *FilesystemQuarantineParams:
		if err := decodePlanTarget(raw, &p.PlanTargetParams); err != nil {
			return nil, nil, err
		}
	case *FilesystemRestoreParams:
		if err := decodePlanTarget(raw, &p.PlanTargetParams); err != nil {
			return nil, nil, err
		}
	default:
		return nil, nil, fmt.Errorf("unhandled params type for %s", action)
	}

	// Keep the raw document for policy input, in the same shape it arrived.
	decoded := map[string]any{}
	if len(raw) > 0 {
		encoded, err := json.Marshal(raw)
		if err != nil {
			return nil, nil, err
		}
		if err := json.Unmarshal(encoded, &decoded); err != nil {
			return nil, nil, err
		}
	}
	return typed, decoded, nil
}

func decodePlanTarget(raw map[string]json.RawMessage, out *PlanTargetParams) error {
	if err := decodeStrict(raw, out, "path", "plan_id", "candidate_id"); err != nil {
		return err
	}
	if err := ValidPath(out.Path); err != nil {
		return err
	}
	if !ValidPlanID(out.PlanID) {
		return fmt.Errorf("invalid plan_id")
	}
	if !ValidCandidateID(out.CandidateID) {
		return fmt.Errorf("invalid candidate_id")
	}
	return nil
}

func decodeStrict(raw map[string]json.RawMessage, out any, allowed ...string) error {
	for key := range raw {
		if !slices.Contains(allowed, key) {
			return fmt.Errorf("unknown param %q", key)
		}
	}
	if len(raw) == 0 {
		return nil
	}
	encoded, err := json.Marshal(raw)
	if err != nil {
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(encoded))
	dec.DisallowUnknownFields()
	if err := dec.Decode(out); err != nil {
		return fmt.Errorf("invalid params: %w", err)
	}
	return nil
}

// StringOrEmpty renders an optional string.
func StringOrEmpty(value *string) string {
	if value == nil {
		return ""
	}
	return strings.TrimSpace(*value)
}
