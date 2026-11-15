// Package api exposes the control plane over HTTP.
//
// Two separate surfaces: operator observations call the read-only gateway
// directly; agent proposals go through the security engine. An agent can never
// reach the observation routes, and the operator never needs a grant to look
// at their own machine.
package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"time"

	"aios/internal/catalog"
	"aios/internal/config"
	"aios/internal/gateway"
	"aios/internal/protocol"
	"aios/internal/runtime"
)

// Version is the control-plane version.
const Version = "0.7.0"

// Server is the HTTP surface.
type Server struct {
	rt *runtime.Runtime
}

// New builds the API server.
func New(rt *runtime.Runtime) *Server { return &Server{rt: rt} }

// Handler returns the mux.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", s.health)
	mux.HandleFunc("/actions/schema", s.schema)
	mux.HandleFunc("/actions/validate", s.validate)
	mux.HandleFunc("/actions/execute", s.execute)
	mux.HandleFunc("/system/status", s.systemStatus)
	mux.HandleFunc("/system/cpu", s.systemCPU)
	mux.HandleFunc("/system/memory", s.systemMemory)
	mux.HandleFunc("/system/hostname", s.systemHostname)
	mux.HandleFunc("/processes", s.processes)
	mux.HandleFunc("/processes/", s.process)
	mux.HandleFunc("/network/connections", s.networkConnections)
	return mux
}

// ListenAndServe binds the configured loopback address.
func (s *Server) ListenAndServe(settings config.Settings) error {
	address := net.JoinHostPort(settings.APIHost, strconv.Itoa(settings.APIPort))
	server := &http.Server{
		Addr: address, Handler: s.Handler(),
		ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 30 * time.Second,
		WriteTimeout: 120 * time.Second, IdleTimeout: 60 * time.Second,
	}
	return server.ListenAndServe()
}

func (s *Server) health(w http.ResponseWriter, _ *http.Request) {
	durable := s.rt.Settings.LedgerPath != ""
	writeJSON(w, http.StatusOK, map[string]any{
		"status": "ok", "version": Version,
		"proc_root":       s.rt.Settings.ProcRoot,
		"gateway_actions": len(s.rt.Gateway.SupportedActions()),
		"ledger":          "jsonl", "ledger_durable": durable,
		"ledger_detail": s.rt.Settings.LedgerPath,
	})
}

func (s *Server) schema(w http.ResponseWriter, _ *http.Request) {
	allowed := make([]string, 0, len(catalog.Catalog))
	for name := range catalog.Catalog {
		allowed = append(allowed, name)
	}
	sort.Strings(allowed)
	forbidden := make([]string, 0, len(catalog.Forbidden))
	for name := range catalog.Forbidden {
		forbidden = append(forbidden, name)
	}
	sort.Strings(forbidden)
	schemas := map[string]any{}
	for _, name := range allowed {
		schemas[name] = schemaFor(name)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"protocol_version": Version, "allowed_actions": allowed,
		"forbidden_actions": forbidden, "params_schema": schemas,
	})
}

func (s *Server) systemStatus(w http.ResponseWriter, r *http.Request) {
	s.observe(w, "system.status", "api-system-status", map[string]any{})
}

func (s *Server) systemCPU(w http.ResponseWriter, r *http.Request) {
	interval, err := floatQuery(r, "interval_s", 0.25, 0, 5)
	if err != nil {
		badRequest(w, err)
		return
	}
	s.observe(w, "system.cpu", "api-system-cpu", map[string]any{"interval_s": interval})
}

func (s *Server) systemMemory(w http.ResponseWriter, r *http.Request) {
	include, err := boolQuery(r, "include_fields", false)
	if err != nil {
		badRequest(w, err)
		return
	}
	s.observe(w, "system.memory", "api-system-memory", map[string]any{"include_fields": include})
}

func (s *Server) systemHostname(w http.ResponseWriter, _ *http.Request) {
	s.observe(w, "system.hostname", "api-system-hostname", map[string]any{})
}

func (s *Server) processes(w http.ResponseWriter, r *http.Request) {
	limit, err := intQuery(r, "limit", 50, 1, 1000)
	if err != nil {
		badRequest(w, err)
		return
	}
	sortBy := r.URL.Query().Get("sort_by")
	if sortBy == "" {
		sortBy = "cpu"
	}
	if sortBy != "cpu" && sortBy != "memory" && sortBy != "pid" && sortBy != "name" {
		badRequest(w, errors.New("sort_by must be cpu, memory, pid, or name"))
		return
	}
	params := map[string]any{"limit": limit, "sort_by": sortBy}
	if filter := r.URL.Query().Get("name_filter"); filter != "" {
		if len(filter) > 64 {
			badRequest(w, errors.New("name_filter is too long"))
			return
		}
		params["name_filter"] = filter
	}
	s.observe(w, "process.list", "api-process-list", params)
}

func (s *Server) process(w http.ResponseWriter, r *http.Request) {
	raw := strings.TrimPrefix(r.URL.Path, "/processes/")
	pid, err := strconv.Atoi(raw)
	if err != nil || pid < 1 || pid > 4_194_303 {
		badRequest(w, errors.New("invalid pid"))
		return
	}
	s.observe(w, "process.inspect", fmt.Sprintf("api-process-inspect-%d", pid),
		map[string]any{"pid": pid})
}

func (s *Server) networkConnections(w http.ResponseWriter, r *http.Request) {
	limit, err := intQuery(r, "limit", 200, 1, 2000)
	if err != nil {
		badRequest(w, err)
		return
	}
	listening, err := boolQuery(r, "listening_only", false)
	if err != nil {
		badRequest(w, err)
		return
	}
	attribute, err := boolQuery(r, "attribute_pids", true)
	if err != nil {
		badRequest(w, err)
		return
	}
	s.observe(w, "network.connections", "api-network-connections", map[string]any{
		"limit": limit, "listening_only": listening, "attribute_pids": attribute,
	})
}

// observe runs a read action directly as the operator.
func (s *Server) observe(w http.ResponseWriter, action, actionID string, params map[string]any) {
	req, err := protocol.NewRequest(action, params, protocol.WithActionID(actionID),
		protocol.WithAgent("api-client"), protocol.WithSession("api"))
	if err != nil {
		badRequest(w, err)
		return
	}
	started := time.Now()
	observation, err := s.rt.Gateway.Execute(req)
	if err != nil {
		writeGatewayError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"action_id": req.ActionID, "state": string(protocol.StateExecuted),
		"success": true, "source": observation.Source,
		"trust_domain": observation.TrustDomain, "timestamp": observation.Timestamp,
		"duration_ms": float64(time.Since(started)) / float64(time.Millisecond),
		"data":        observation.Data,
	})
}

func (s *Server) validate(w http.ResponseWriter, r *http.Request) {
	var payload map[string]any
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&payload); err != nil {
		badRequest(w, errors.New("invalid JSON body"))
		return
	}
	rawType, _ := payload["type"].(string)
	fail := func(reason, detail string) {
		writeJSON(w, http.StatusOK, map[string]any{
			"valid": false, "state": string(protocol.StateDenied),
			"error": reason, "detail": detail,
		})
	}
	if catalog.Forbidden[rawType] {
		fail("forbidden_action", rawType+" is not permitted by the AIOS action protocol")
		return
	}
	if _, ok := catalog.Lookup(rawType); !ok {
		fail("unknown_action", fmt.Sprintf("unknown action type: %q", rawType))
		return
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		fail("invalid_action", err.Error())
		return
	}
	req, err := protocol.ParseRequest(encoded)
	if err != nil {
		fail("invalid_action", truncate(err.Error(), 1000))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"valid": true, "action_id": req.ActionID, "type": req.ActionName(),
		"validated_params": asMap(req.Typed), "trust_domain": string(req.Trust),
		"state": string(protocol.StateValidated),
	})
}

// executeRequest is the agent proposal plus who is making it.
type executeRequest struct {
	ActionID       string         `json:"action_id"`
	Type           string         `json:"type"`
	Params         map[string]any `json:"params"`
	AgentID        string         `json:"agent_id"`
	SessionID      string         `json:"session_id"`
	Origin         string         `json:"origin"`
	RequestedScope map[string]any `json:"requested_scope"`
	Intent         *string        `json:"intent"`
	DryRun         bool           `json:"dry_run"`
}

func (s *Server) execute(w http.ResponseWriter, r *http.Request) {
	var payload executeRequest
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&payload); err != nil {
		badRequest(w, errors.New("invalid request: "+err.Error()))
		return
	}
	origin := protocol.Origin(payload.Origin)
	if origin == "" {
		origin = protocol.OriginAI
	}
	if origin != protocol.OriginAI && origin != protocol.OriginUser {
		badRequest(w, fmt.Errorf("origin %q is not accepted on the agent path", origin))
		return
	}
	agent := payload.AgentID
	if agent == "" {
		agent = "local-agent"
	}
	session := payload.SessionID
	if session == "" {
		session = "api"
	}
	request, err := protocol.NewRequest(payload.Type, payload.Params,
		protocol.WithActionID(payload.ActionID), protocol.WithAgent(agent),
		protocol.WithSession(session), protocol.WithOrigin(origin),
		protocol.WithScope(payload.RequestedScope), protocol.WithIntentValue(payload.Intent))
	if err != nil {
		badRequest(w, err)
		return
	}
	var verdict any
	if payload.DryRun {
		verdict = s.rt.Engine.Authorize(request, nil, nil)
	} else {
		verdict = s.rt.Engine.Process(request, nil, nil)
	}
	encoded, err := json.Marshal(verdict)
	if err != nil {
		badRequest(w, err)
		return
	}
	var body map[string]any
	_ = json.Unmarshal(encoded, &body)
	body["agent_id"] = request.AgentID
	body["trust_domain"] = string(request.Trust)
	if observation, ok := body["observation"].(map[string]any); ok {
		body["source"] = observation["source"]
		body["data"] = observation["data"]
	}
	if capability, ok := body["capability"].(map[string]any); ok {
		body["capability"] = capability["matched_capability"]
	}
	delete(body, "observation")
	if decision, _ := body["decision"].(string); decision == "DENY" {
		reason, _ := body["denial_reason"].(string)
		if reason == "" {
			reason = "denied"
		}
		w.Header().Set("X-AIOS-Reason", reason)
		writeJSON(w, http.StatusForbidden, body)
		return
	}
	writeJSON(w, http.StatusOK, body)
}

// --- helpers ---------------------------------------------------------------

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func badRequest(w http.ResponseWriter, err error) {
	writeJSON(w, http.StatusBadRequest, map[string]any{
		"error": "invalid_request", "detail": err.Error(),
	})
}

func writeGatewayError(w http.ResponseWriter, err error) {
	status := http.StatusBadRequest
	var notPermitted gateway.ActionNotPermitted
	var precondition gateway.PreconditionFailed
	if errors.As(err, &notPermitted) || errors.As(err, &precondition) {
		status = http.StatusForbidden
	}
	writeJSON(w, status, map[string]any{"error": "refused", "detail": err.Error()})
}

func intQuery(r *http.Request, name string, fallback, minimum, maximum int) (int, error) {
	raw := r.URL.Query().Get(name)
	if raw == "" {
		return fallback, nil
	}
	value, err := strconv.Atoi(raw)
	if err != nil || value < minimum || value > maximum {
		return 0, fmt.Errorf("%s must be between %d and %d", name, minimum, maximum)
	}
	return value, nil
}

func floatQuery(r *http.Request, name string, fallback, minimum, maximum float64) (float64, error) {
	raw := r.URL.Query().Get(name)
	if raw == "" {
		return fallback, nil
	}
	value, err := strconv.ParseFloat(raw, 64)
	if err != nil || value < minimum || value > maximum {
		return 0, fmt.Errorf("%s must be between %g and %g", name, float64(minimum), float64(maximum))
	}
	return value, nil
}

func boolQuery(r *http.Request, name string, fallback bool) (bool, error) {
	raw := r.URL.Query().Get(name)
	if raw == "" {
		return fallback, nil
	}
	value, err := strconv.ParseBool(raw)
	if err != nil {
		return false, fmt.Errorf("%s must be true or false", name)
	}
	return value, nil
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

func truncate(value string, limit int) string {
	if len(value) <= limit {
		return value
	}
	return value[:limit]
}

func schemaFor(action string) map[string]any {
	params := protocol.ParamsFor(action)
	properties := map[string]any{}
	if params != nil {
		collectFields(reflect.TypeOf(params), properties)
	}
	return map[string]any{
		"type": "object", "additionalProperties": false, "properties": properties,
	}
}

func collectFields(t reflect.Type, out map[string]any) {
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	if t.Kind() != reflect.Struct {
		return
	}
	for i := 0; i < t.NumField(); i++ {
		field := t.Field(i)
		if field.Anonymous {
			collectFields(field.Type, out)
			continue
		}
		name := strings.Split(field.Tag.Get("json"), ",")[0]
		if name == "" || name == "-" {
			continue
		}
		out[name] = map[string]any{"type": jsonType(field.Type)}
	}
}

func jsonType(t reflect.Type) string {
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	switch t.Kind() {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return "integer"
	case reflect.Float32, reflect.Float64:
		return "number"
	case reflect.Bool:
		return "boolean"
	case reflect.Slice, reflect.Array:
		return "array"
	case reflect.Map, reflect.Struct:
		return "object"
	default:
		return "string"
	}
}
