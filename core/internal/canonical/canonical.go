// Package canonical renders the canonical JSON used for hashing and signing.
//
// The Python reference uses json.dumps(sort_keys=True, separators=(",", ":"),
// ensure_ascii=False). Go's encoder sorts map keys and, with HTML escaping
// off, leaves non-ASCII text alone. Both sides must produce the same bytes or
// a plan hashed by one cannot be verified by the other.
package canonical

import (
	"bytes"
	"encoding/json"
)

// Marshal returns compact canonical JSON with a trailing newline removed.
func Marshal(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	out := buf.Bytes()
	if len(out) > 0 && out[len(out)-1] == '\n' {
		out = out[:len(out)-1]
	}
	return out, nil
}
