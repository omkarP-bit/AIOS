// Package model holds the data shapes shared by the scanner, plans, and the
// executor. The JSON names are the protocol, so they are spelled out.
package model

import (
	"encoding/json"
	"time"
)

// Timestamp renders UTC times the way the Python reference does: RFC 3339
// with microseconds only when they are non-zero, and a trailing Z.
type Timestamp struct {
	time.Time
}

// FormatTime is the canonical wire form of a time.
func FormatTime(t time.Time) string {
	return t.UTC().Format("2006-01-02T15:04:05.999999Z")
}

// ParseTime accepts the canonical form and ordinary RFC 3339.
func ParseTime(value string) (time.Time, error) {
	return time.Parse(time.RFC3339Nano, value)
}

// MarshalJSON implements json.Marshaler.
func (t Timestamp) MarshalJSON() ([]byte, error) {
	return json.Marshal(FormatTime(t.Time))
}

// UnmarshalJSON implements json.Unmarshaler.
func (t *Timestamp) UnmarshalJSON(data []byte) error {
	var text string
	if err := json.Unmarshal(data, &text); err != nil {
		return err
	}
	parsed, err := ParseTime(text)
	if err != nil {
		return err
	}
	t.Time = parsed
	return nil
}
