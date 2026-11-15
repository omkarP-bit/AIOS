// Package ledger appends the audit trail. Writes are best-effort at the call
// site: losing a row is bad, re-running an authorized action is worse.
package ledger

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"

	"aios/internal/model"
)

// Entry is one audit row.
type Entry struct {
	ActionID         string          `json:"action_id"`
	SessionID        string          `json:"session_id"`
	AgentID          string          `json:"agent_id"`
	Action           string          `json:"action"`
	State            string          `json:"state"`
	Risk             string          `json:"risk"`
	Decision         string          `json:"decision"`
	Reason           string          `json:"reason"`
	Capability       *string         `json:"capability"`
	CapabilityReason *string         `json:"capability_reason"`
	Target           *string         `json:"target"`
	PolicySource     *string         `json:"policy_source"`
	DurationMS       *float64        `json:"duration_ms"`
	At               model.Timestamp `json:"at"`
	Detail           *string         `json:"detail"`
	DenialReason     *string         `json:"denial_reason"`
}

// Ledger keeps entries in memory and, when Path is set, appends them as JSONL.
type Ledger struct {
	mu      sync.Mutex
	entries []Entry
	path    string
}

// New builds a ledger. An empty path keeps it in memory only.
func New(path string) (*Ledger, error) {
	l := &Ledger{path: path}
	if path != "" {
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			return nil, err
		}
		file, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
		if err != nil {
			return nil, err
		}
		if err := file.Close(); err != nil {
			return nil, err
		}
		if err := l.load(); err != nil {
			return nil, err
		}
	}
	return l, nil
}

// load replays the durable log so a restarted process can report history. A
// partial trailing line from a crash is skipped rather than failing startup.
func (l *Ledger) load() error {
	file, err := os.Open(l.path)
	if err != nil {
		return err
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 4096), 1<<20)
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		var entry Entry
		if err := json.Unmarshal(line, &entry); err != nil {
			continue
		}
		l.entries = append(l.entries, entry)
	}
	return scanner.Err()
}

// Record appends one row and fsyncs the durable log.
func (l *Ledger) Record(entry Entry) error {
	if entry.At.IsZero() {
		entry.At = model.Timestamp{Time: time.Now().UTC().Truncate(time.Microsecond)}
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.entries = append(l.entries, entry)
	if l.path == "" {
		return nil
	}
	file, err := os.OpenFile(l.path, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer file.Close()
	encoded, err := json.Marshal(entry)
	if err != nil {
		return err
	}
	if _, err := file.Write(append(encoded, '\n')); err != nil {
		return err
	}
	return file.Sync()
}

// Entries returns a copy of the in-memory trail.
func (l *Ledger) Entries() []Entry {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]Entry(nil), l.entries...)
}

// ByAction returns the trail for one action id.
func (l *Ledger) ByAction(actionID string) []Entry {
	out := []Entry{}
	for _, entry := range l.Entries() {
		if entry.ActionID == actionID {
			out = append(out, entry)
		}
	}
	return out
}

// States returns just the state sequence for one action.
func (l *Ledger) States(actionID string) []string {
	out := []string{}
	for _, entry := range l.ByAction(actionID) {
		out = append(out, entry.State)
	}
	return out
}
