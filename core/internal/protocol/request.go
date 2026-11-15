// Package protocol defines the closed action protocol.
//
// There is no command string here and no way to add one: the envelope is
// strict, the action set is closed, and every params object is validated
// against one typed shape. The model cannot express an operation the catalog
// does not already describe.
package protocol

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"aios/internal/catalog"
)

// Origin is where a proposal came from.
type Origin string

const (
	OriginKernel   Origin = "kernel"
	OriginSysfs    Origin = "sysfs"
	OriginGateway  Origin = "gateway"
	OriginSecurity Origin = "security"
	OriginPolicy   Origin = "policy"
	OriginAI       Origin = "ai"
	OriginUser     Origin = "user"
	OriginExternal Origin = "external"
	OriginTool     Origin = "tool"
)

// TrustDomain is derived from origin, never supplied by the proposer.
type TrustDomain string

const (
	TrustT0 TrustDomain = "T0"
	TrustT1 TrustDomain = "T1"
	TrustT2 TrustDomain = "T2"
	TrustT3 TrustDomain = "T3"
	TrustT4 TrustDomain = "T4"
)

// TrustFor maps origin to trust domain.
func TrustFor(o Origin) (TrustDomain, error) {
	switch o {
	case OriginKernel, OriginSysfs:
		return TrustT0, nil
	case OriginGateway:
		return TrustT2, nil
	case OriginSecurity, OriginPolicy:
		return TrustT1, nil
	case OriginAI, OriginUser:
		return TrustT3, nil
	case OriginExternal, OriginTool:
		return TrustT4, nil
	default:
		return "", fmt.Errorf("unknown origin: %q", o)
	}
}

// Trusted reports whether a domain is inside the boundary.
func (t TrustDomain) Trusted() bool {
	return t == TrustT0 || t == TrustT1 || t == TrustT2
}

// State is the action lifecycle.
type State string

const (
	StateProposed   State = "PROPOSED"
	StateValidated  State = "VALIDATED"
	StateAuthorized State = "AUTHORIZED"
	StateExecuted   State = "EXECUTED"
	StateObserved   State = "OBSERVED"
	StateCompleted  State = "COMPLETED"
	StateDenied     State = "DENIED"
	StateFailed     State = "FAILED"
	StateViolation  State = "VIOLATION"
)

var transitions = map[State]map[State]bool{
	StateProposed:   {StateValidated: true, StateDenied: true, StateFailed: true},
	StateValidated:  {StateAuthorized: true, StateDenied: true, StateFailed: true},
	StateAuthorized: {StateExecuted: true, StateDenied: true, StateFailed: true},
	StateExecuted:   {StateObserved: true, StateCompleted: true, StateFailed: true},
	StateObserved:   {StateCompleted: true, StateViolation: true},
	StateCompleted:  {}, StateDenied: {}, StateFailed: {}, StateViolation: {},
}

// CanTransition reports whether from -> to is a legal edge.
func CanTransition(from, to State) bool {
	return transitions[from][to]
}

// AssertTransition panics-free equivalent of the Python assertion.
func AssertTransition(from, to State) error {
	if !CanTransition(from, to) {
		return fmt.Errorf("illegal action lifecycle transition: %s -> %s", from, to)
	}
	return nil
}

// Request is a validated action proposal.
type Request struct {
	ActionID       string
	AgentID        string
	SessionID      string
	Type           string
	Params         map[string]any
	Typed          Params
	Intent         *string
	RequestedScope map[string]any
	Origin         Origin
	Trust          TrustDomain
}

// Params is implemented by each typed parameter object.
type Params interface{ actionParams() }

// ActionName returns the protocol action name.
func (r *Request) ActionName() string { return r.Type }

// Target returns the resource named by the params, or "" for unscoped actions.
func (r *Request) Target() string {
	switch catalog.ScopeDimensionFor(r.Type) {
	case "path":
		switch p := r.Typed.(type) {
		case *FilesystemListParams:
			if p.Path != nil {
				return *p.Path
			}
		case *FilesystemStatParams:
			return p.Path
		case *FilesystemReadParams:
			return p.Path
		case *FilesystemCleanupScanParams:
			return p.Path
		case *FilesystemQuarantineParams:
			return p.Path
		case *FilesystemRestoreParams:
			return p.Path
		}
	case "pid":
		if p, ok := r.Typed.(*ProcessInspectParams); ok {
			return fmt.Sprintf("%d", p.PID)
		}
	}
	return ""
}

// WireRequest is the strict JSON shape accepted from the edge.
type WireRequest struct {
	ActionID       string                     `json:"action_id"`
	AgentID        string                     `json:"agent_id"`
	SessionID      string                     `json:"session_id"`
	Type           string                     `json:"type"`
	Params         map[string]json.RawMessage `json:"params"`
	Intent         *string                    `json:"intent"`
	RequestedScope map[string]json.RawMessage `json:"requested_scope"`
	Origin         Origin                     `json:"origin"`
}

// DecodeWire parses an envelope, rejecting unknown fields.
func DecodeWire(data []byte) (*WireRequest, error) {
	var w WireRequest
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&w); err != nil {
		return nil, fmt.Errorf("invalid request: %w", err)
	}
	if dec.More() {
		return nil, fmt.Errorf("invalid request: trailing data")
	}
	return &w, nil
}

var (
	actionIDRe  = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)
	agentIDRe   = regexp.MustCompile(`^[A-Za-z0-9_.-]+$`)
	sessionIDRe = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)
	planIDRe    = regexp.MustCompile(`^plan-[A-Za-z0-9_-]+$`)
	candidateRe = regexp.MustCompile(`^c-[A-Za-z0-9_-]+$`)
)

// FromWire validates and builds a Request. Missing action_id is generated, as
// the CLI agent path does; an explicit id is validated like any other field.
func FromWire(w *WireRequest) (*Request, error) {
	if w.Type == "" {
		return nil, fmt.Errorf("missing action type")
	}
	if catalog.Forbidden[w.Type] {
		return nil, fmt.Errorf("%s is forbidden", w.Type)
	}
	if _, ok := catalog.Lookup(w.Type); !ok {
		return nil, fmt.Errorf("unknown action %s", w.Type)
	}
	if w.ActionID == "" {
		w.ActionID = NewActionID("act")
	}
	if !actionIDRe.MatchString(w.ActionID) || len(w.ActionID) < 8 || len(w.ActionID) > 64 {
		return nil, fmt.Errorf("invalid action_id")
	}
	if w.AgentID == "" {
		w.AgentID = "local-agent"
	}
	if !agentIDRe.MatchString(w.AgentID) || len(w.AgentID) > 64 {
		return nil, fmt.Errorf("invalid agent_id")
	}
	if w.SessionID == "" {
		w.SessionID = "cli"
	}
	if !sessionIDRe.MatchString(w.SessionID) || len(w.SessionID) > 64 {
		return nil, fmt.Errorf("invalid session_id")
	}
	if w.Intent != nil && len(*w.Intent) > 256 {
		return nil, fmt.Errorf("intent exceeds 256 characters")
	}
	origin := w.Origin
	if origin == "" {
		origin = OriginAI
	}
	trust, err := TrustFor(origin)
	if err != nil {
		return nil, err
	}

	typed, raw, err := validateParams(w.Type, w.Params)
	if err != nil {
		return nil, err
	}

	scope := map[string]any{}
	for key, value := range w.RequestedScope {
		var decoded any
		if err := json.Unmarshal(value, &decoded); err != nil {
			return nil, fmt.Errorf("requested_scope.%s: %w", key, err)
		}
		scope[key] = decoded
	}

	req := &Request{
		ActionID:       w.ActionID,
		AgentID:        w.AgentID,
		SessionID:      w.SessionID,
		Type:           w.Type,
		Params:         raw,
		Typed:          typed,
		Intent:         w.Intent,
		RequestedScope: scope,
		Origin:         origin,
		Trust:          trust,
	}
	if err := req.CheckScopeConsistency(); err != nil {
		return nil, err
	}
	return req, nil
}

// ParseRequest is the byte-level entry point.
func ParseRequest(data []byte) (*Request, error) {
	w, err := DecodeWire(data)
	if err != nil {
		return nil, err
	}
	return FromWire(w)
}

// NewRequest builds a request from typed params, for the CLI and tests.
func NewRequest(action string, params map[string]any, opts ...RequestOption) (*Request, error) {
	options := requestOptions{
		actionID: NewActionID("act"), agentID: "local-agent", sessionID: "cli",
		origin: OriginAI, scope: map[string]any{},
	}
	for _, opt := range opts {
		opt(&options)
	}
	wireParams := map[string]json.RawMessage{}
	for key, value := range params {
		encoded, err := json.Marshal(value)
		if err != nil {
			return nil, err
		}
		wireParams[key] = encoded
	}
	wireScope := map[string]json.RawMessage{}
	for key, value := range options.scope {
		encoded, err := json.Marshal(value)
		if err != nil {
			return nil, err
		}
		wireScope[key] = encoded
	}
	return FromWire(&WireRequest{
		ActionID: options.actionID, AgentID: options.agentID,
		SessionID: options.sessionID, Type: action, Params: wireParams,
		Intent: options.intent, RequestedScope: wireScope, Origin: options.origin,
	})
}

type requestOptions struct {
	actionID  string
	agentID   string
	sessionID string
	origin    Origin
	intent    *string
	scope     map[string]any
}

// RequestOption customises NewRequest.
type RequestOption func(*requestOptions)

// WithActionID sets the action id.
func WithActionID(id string) RequestOption { return func(o *requestOptions) { o.actionID = id } }

// WithAgent sets the agent id.
func WithAgent(id string) RequestOption { return func(o *requestOptions) { o.agentID = id } }

// WithSession sets the session id.
func WithSession(id string) RequestOption { return func(o *requestOptions) { o.sessionID = id } }

// WithOrigin sets the origin.
func WithOrigin(origin Origin) RequestOption { return func(o *requestOptions) { o.origin = origin } }

// WithIntent sets the intent text.
func WithIntent(text string) RequestOption { return func(o *requestOptions) { o.intent = &text } }

// WithIntentValue sets the intent, preserving nil.
func WithIntentValue(text *string) RequestOption {
	return func(o *requestOptions) { o.intent = text }
}

// WithScope sets the declared scope.
func WithScope(scope map[string]any) RequestOption {
	return func(o *requestOptions) { o.scope = scope }
}

// CheckScopeConsistency rejects a declared scope that disagrees with the
// params. A claim cannot widen the real target.
func (r *Request) CheckScopeConsistency() error {
	if len(r.RequestedScope) == 0 {
		return nil
	}
	target := r.Target()
	for key, value := range r.RequestedScope {
		switch key {
		case "path":
			text, ok := value.(string)
			if !ok || target == "" || NormalisePath(text) != NormalisePath(target) {
				return fmt.Errorf("requested_scope.path does not match the action target")
			}
		case "pid":
			if target == "" || fmt.Sprint(value) != target {
				return fmt.Errorf("requested_scope.pid does not match the action target")
			}
		case "uid":
			// uid is not used by any current action; accepted but inert.
		default:
			return fmt.Errorf("requested_scope key %q is not a scope dimension", key)
		}
		if catalog.ScopeDimensionFor(r.Type) == "none" {
			return fmt.Errorf("%s has no scope, so requested_scope must be empty", r.Type)
		}
	}
	return nil
}

// NormalisePath collapses "." and ".." and duplicate separators.
func NormalisePath(path string) string {
	if path == "" {
		return ""
	}
	parts := []string{}
	for _, segment := range strings.Split(path, "/") {
		switch segment {
		case "", ".":
			continue
		case "..":
			if len(parts) > 0 {
				parts = parts[:len(parts)-1]
			}
		default:
			parts = append(parts, segment)
		}
	}
	if len(parts) == 0 {
		return "/"
	}
	return "/" + strings.Join(parts, "/")
}

// NewActionID returns "prefix-" plus 16 hex characters.
func NewActionID(prefix string) string {
	buf := make([]byte, 8)
	if _, err := rand.Read(buf); err != nil {
		panic("crypto/rand unavailable: " + err.Error())
	}
	return prefix + "-" + hex.EncodeToString(buf)
}

// ValidPlanID reports whether a plan id has the expected shape.
func ValidPlanID(id string) bool {
	return len(id) >= 8 && len(id) <= 64 && planIDRe.MatchString(id)
}

// ValidCandidateID reports whether a candidate id has the expected shape.
func ValidCandidateID(id string) bool {
	return len(id) >= 8 && len(id) <= 64 && candidateRe.MatchString(id)
}

// ValidPath rejects empty strings, NUL, and over-long paths.
func ValidPath(path string) error {
	if path == "" {
		return fmt.Errorf("path must not be empty")
	}
	if len(path) > 4096 {
		return fmt.Errorf("path is too long")
	}
	if strings.ContainsRune(path, 0) {
		return fmt.Errorf("path must not contain NUL")
	}
	return nil
}
