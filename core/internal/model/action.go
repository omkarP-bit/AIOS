package model

import (
	"bytes"
	"encoding/json"
	"errors"
)

// Candidate is one file the scanner proposes for cleanup.
type Candidate struct {
	CandidateID string   `json:"candidate_id"`
	Path        string   `json:"path"`
	Dev         uint64   `json:"dev"`
	Ino         uint64   `json:"ino"`
	SizeBytes   int64    `json:"size_bytes"`
	MtimeNS     int64    `json:"mtime_ns"`
	Mode        uint32   `json:"mode"`
	UID         uint32   `json:"uid"`
	Reason      string   `json:"reason"`
	Tags        []string `json:"tags"`
}

// ScanResult is the read-only output of filesystem.cleanup_scan.
type ScanResult struct {
	Root         string      `json:"root"`
	Candidates   []Candidate `json:"candidates"`
	Total        int         `json:"total"`
	TotalBytes   int64       `json:"total_bytes"`
	ScannedFiles int         `json:"scanned_files"`
	Skipped      int         `json:"skipped"`
	Truncated    bool        `json:"truncated"`
	GeneratedAt  Timestamp   `json:"generated_at"`
}

// QuarantineRecord is the sidecar written next to a quarantined payload.
type QuarantineRecord struct {
	PlanID        string    `json:"plan_id"`
	PlanHash      string    `json:"plan_hash"`
	CandidateID   string    `json:"candidate_id"`
	OriginalPath  string    `json:"original_path"`
	Dev           uint64    `json:"dev"`
	Ino           uint64    `json:"ino"`
	SizeBytes     int64     `json:"size_bytes"`
	MtimeNS       int64     `json:"mtime_ns"`
	Mode          uint32    `json:"mode"`
	UID           uint32    `json:"uid"`
	QuarantinedAt Timestamp `json:"quarantined_at"`
	ApprovedBy    string    `json:"approved_by"`
}

// StepResult is the per-step outcome of an executor run.
type StepResult struct {
	Action         string         `json:"action"`
	CandidateID    string         `json:"candidate_id"`
	Path           string         `json:"path"`
	Status         string         `json:"status"`
	Detail         *string        `json:"detail"`
	QuarantinePath *string        `json:"quarantine_path"`
	BytesMoved     int64          `json:"bytes_moved"`
	Target         string         `json:"target,omitempty"`
	PID            int            `json:"pid,omitempty"`
	Signal         string         `json:"signal,omitempty"`
	Data           map[string]any `json:"data,omitempty"`
}

// ExecutionResult is the executor's report for one plan.
type ExecutionResult struct {
	PlanID     string       `json:"plan_id"`
	PlanHash   string       `json:"plan_hash"`
	Steps      []StepResult `json:"steps"`
	Applied    int          `json:"applied"`
	Skipped    int          `json:"skipped"`
	Failed     int          `json:"failed"`
	TotalBytes int64        `json:"total_bytes"`
}

// DecodeStrict decodes one JSON document, rejecting unknown fields.
func DecodeStrict(data []byte, out any) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(out); err != nil {
		return err
	}
	if dec.More() {
		return errors.New("trailing data after JSON document")
	}
	return nil
}
