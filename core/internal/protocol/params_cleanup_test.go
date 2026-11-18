package protocol

import (
	"strings"
	"testing"
)

// ASI02-002: filesystem.find accepts only the documented criteria shape.
func TestFilesystemFindParams(t *testing.T) {
	req, err := NewRequest("filesystem.find", map[string]any{
		"root": "/tmp/work", "min_age_days": 30, "min_size_bytes": 1024,
		"extensions": []any{"*.LOG", "log", ".tmp"}, "max_results": 25,
	})
	if err != nil {
		t.Fatal(err)
	}
	p, ok := req.Typed.(*FilesystemFindParams)
	if !ok {
		t.Fatalf("wrong params type: %T", req.Typed)
	}
	if p.Root != "/tmp/work" || req.Target() != "/tmp/work" {
		t.Fatalf("root was not bound: %+v target=%q", p, req.Target())
	}
	if len(p.Extensions) != 2 || p.Extensions[0] != ".log" || p.Extensions[1] != ".tmp" {
		t.Fatalf("extensions were not normalised: %v", p.Extensions)
	}
	if p.MaxResults != 25 {
		t.Fatalf("max_results was not bound: %d", p.MaxResults)
	}
}

// ASI02-003: roots are validated before any filesystem call.
func TestFilesystemFindRejectsUnsafeRoots(t *testing.T) {
	roots := []string{"", "relative/path", "~/Downloads", "/tmp/x\x00y", "/tmp/../etc", "/tmp/\x1b[2J"}
	for _, root := range roots {
		_, err := NewRequest("filesystem.find", map[string]any{"root": root, "max_results": 5})
		if err == nil {
			t.Errorf("accepted unsafe root %q", root)
		}
	}
}

// ASI02-004: trash takes a plan id and nothing else. A model cannot smuggle a
// path or a candidate list through the request.
func TestFilesystemTrashIsPlanOnly(t *testing.T) {
	if _, err := NewRequest("filesystem.trash", map[string]any{"plan_id": "plan-0123456789abcdef01234567"}); err != nil {
		t.Fatalf("valid plan_id rejected: %v", err)
	}
	attacks := []map[string]any{
		{"plan_id": "plan-0123456789abcdef01234567", "path": "/etc/shadow"},
		{"plan_id": "plan-0123456789abcdef01234567", "paths": []any{"/etc/shadow"}},
		{"plan_id": "plan-0123456789abcdef01234567", "candidate_id": "c-0123456789abcdef"},
		{"plan_id": "plan-0123456789abcdef01234567", "approved": true},
		{"path": "/etc/shadow"},
	}
	for _, params := range attacks {
		if _, err := NewRequest("filesystem.trash", params); err == nil {
			t.Errorf("accepted attack params %v", params)
		}
	}
}

// ASI05-002: permanent delete stays outside the protocol even when requested
// with otherwise valid parameters.
func TestFilesystemDeleteIsForbidden(t *testing.T) {
	for _, name := range []string{"filesystem.delete", "filesystem.rm", "filesystem.purge"} {
		if _, err := NewRequest(name, map[string]any{"path": "/tmp/x"}); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}

// ASI02-005: a hand-built envelope with a forbidden action or unknown fields
// fails closed without panicking.
func TestMalformedWireRequestFailsClosed(t *testing.T) {
	documents := []string{
		`{"type":"filesystem.delete","params":{}}`,
		`{"type":"filesystem.find","params":{},"origin":"system"}`,
		`{"type":"filesystem.find","params":{"root":"/tmp","extra":1}}`,
		`{not json}`,
		``,
	}
	for _, document := range documents {
		req, err := ParseRequest([]byte(document))
		if err == nil && req != nil {
			t.Errorf("accepted malformed request %q", document)
		}
	}
	if _, err := DecodeWire([]byte(`{"type":"filesystem.find","params":{},"surprise":true}`)); err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("unknown field not rejected: %v", err)
	}
}
