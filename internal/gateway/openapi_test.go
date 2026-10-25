package gateway_test

import (
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/Praeviso/AgentSSH/internal/approval"
	"github.com/Praeviso/AgentSSH/internal/audit"
	"github.com/Praeviso/AgentSSH/internal/gateway"
	"github.com/Praeviso/AgentSSH/internal/inventory"
	"github.com/Praeviso/AgentSSH/internal/remote"
	"github.com/Praeviso/AgentSSH/internal/runner"
)

// openAPI fetches the gateway's OpenAPI document, without a token.
func openAPI(t *testing.T, f *fixture) map[string]any {
	t.Helper()
	got := bearer(t, f, remote.PathAPIOpenAPI, "")
	var doc map[string]any
	if got.status != http.StatusOK || json.Unmarshal(got.raw, &doc) != nil {
		t.Fatalf("openapi.json: %d %.300s", got.status, got.raw)
	}
	return doc
}

// lookup follows a JSON pointer ("#/components/schemas/Run") in doc.
func lookup(doc map[string]any, ref string) (any, error) {
	var node any = doc
	for _, part := range strings.Split(strings.TrimPrefix(ref, "#/"), "/") {
		object, ok := node.(map[string]any)
		if !ok || object[part] == nil {
			return nil, fmt.Errorf("unresolved $ref %s", ref)
		}
		node = object[part]
	}
	return node, nil
}

// validate checks value against schema, for the JSON Schema subset the
// document uses: $ref, type (one or a list), properties, required,
// additionalProperties false, items and enum.
func validate(doc map[string]any, schema any, value any, at string) error {
	s, _ := schema.(map[string]any)
	if ref, ok := s["$ref"].(string); ok {
		target, err := lookup(doc, ref)
		if err != nil {
			return err
		}
		return validate(doc, target, value, at)
	}
	if types, ok := s["type"]; ok {
		var allowed []string
		switch t := types.(type) {
		case string:
			allowed = []string{t}
		case []any:
			for _, one := range t {
				allowed = append(allowed, one.(string))
			}
		}
		if !slices.Contains(allowed, jsonType(value)) && (jsonType(value) != "integer" || !slices.Contains(allowed, "number")) {
			return fmt.Errorf("%s: %s, want %v", at, jsonType(value), allowed)
		}
	}
	if enum, ok := s["enum"].([]any); ok && !slices.Contains(enum, value) {
		return fmt.Errorf("%s: %v is not one of %v", at, value, enum)
	}
	if object, ok := value.(map[string]any); ok {
		properties, _ := s["properties"].(map[string]any)
		required, _ := s["required"].([]any)
		for _, name := range required {
			if _, ok := object[name.(string)]; !ok {
				return fmt.Errorf("%s: missing %s", at, name)
			}
		}
		for name, v := range object {
			property, known := properties[name]
			if !known {
				if s["additionalProperties"] == false {
					return fmt.Errorf("%s: %s is not in the schema", at, name)
				}
				continue
			}
			if err := validate(doc, property, v, at+"."+name); err != nil {
				return err
			}
		}
	}
	if list, ok := value.([]any); ok && s["items"] != nil {
		for i, item := range list {
			if err := validate(doc, s["items"], item, fmt.Sprintf("%s[%d]", at, i)); err != nil {
				return err
			}
		}
	}
	return nil
}

func jsonType(value any) string {
	switch v := value.(type) {
	case nil:
		return "null"
	case bool:
		return "boolean"
	case string:
		return "string"
	case float64:
		if v == math.Trunc(v) {
			return "integer"
		}
		return "number"
	case []any:
		return "array"
	case map[string]any:
		return "object"
	}
	return "unknown"
}

type operation struct {
	method, path string
	spec         map[string]any
}

func operations(doc map[string]any) []operation {
	var ops []operation
	for path, item := range doc["paths"].(map[string]any) {
		for method, spec := range item.(map[string]any) {
			ops = append(ops, operation{strings.ToUpper(method), path, spec.(map[string]any)})
		}
	}
	sort.Slice(ops, func(i, j int) bool { return ops[i].method+ops[i].path < ops[j].method+ops[j].path })
	return ops
}

// requestBody returns an operation's request schema and example.
func requestBody(op operation) (schema, example any, ok bool) {
	body, ok := op.spec["requestBody"].(map[string]any)
	if !ok {
		return nil, nil, false
	}
	media := body["content"].(map[string]any)["application/json"].(map[string]any)
	return media["schema"], media["example"], true
}

func responseSchema(doc map[string]any, op operation) (any, error) {
	ok, found := op.spec["responses"].(map[string]any)["200"].(map[string]any)
	if !found {
		return nil, fmt.Errorf("%s %s documents no 200 answer", op.method, op.path)
	}
	return ok["content"].(map[string]any)["application/json"].(map[string]any)["schema"], nil
}

// The served document is OpenAPI 3.1 for this gateway, documents exactly the
// routes the gateway serves, resolves every reference, and its examples fit
// their own schemas.
func TestTheOpenAPIDocumentMatchesTheRoutes(t *testing.T) {
	f := enrolledGateway(t)
	doc := openAPI(t, f)
	if doc["openapi"] != "3.1.0" {
		t.Fatalf("openapi version %v", doc["openapi"])
	}
	if servers, _ := doc["servers"].([]any); len(servers) != 1 || servers[0].(map[string]any)["url"] != f.base {
		t.Fatalf("servers %v, want %s", doc["servers"], f.base)
	}
	if _, err := lookup(doc, "#/components/securitySchemes/bearer"); err != nil {
		t.Fatal(err)
	}
	var documented []string
	for _, op := range operations(doc) {
		documented = append(documented, op.method+" "+op.path)
		if op.spec["operationId"] == nil || op.spec["summary"] == nil {
			t.Errorf("%s %s lacks an operationId or summary", op.method, op.path)
		}
		if schema, example, ok := requestBody(op); ok {
			if err := validate(doc, schema, example, op.path+" example"); err != nil {
				t.Errorf("%v", err)
			}
		}
		if _, err := responseSchema(doc, op); err != nil {
			t.Error(err)
		}
	}
	served := f.server.OpenRoutes()
	sort.Strings(served)
	sort.Strings(documented)
	if strings.Join(served, "\n") != strings.Join(documented, "\n") {
		t.Fatalf("served routes:\n%s\ndocumented operations:\n%s", strings.Join(served, "\n"), strings.Join(documented, "\n"))
	}
	// Every $ref anywhere resolves.
	refs := regexp.MustCompile(`"\$ref":"([^"]+)"`)
	raw, _ := json.Marshal(doc)
	for _, m := range refs.FindAllStringSubmatch(string(raw), -1) {
		if _, err := lookup(doc, m[1]); err != nil {
			t.Error(err)
		}
	}
}

// Every documented operation, sent with the document's example payload (its
// IDs replaced by live ones), succeeds against a gateway and answers what its
// schema says.
func TestEveryDocumentedOperationSucceedsWithItsExample(t *testing.T) {
	f, _ := execGateway(t)
	issued := activeTokenDevice(t, f)
	doc := openAPI(t, f)
	byPath := map[string]operation{}
	for _, op := range operations(doc) {
		byPath[op.method+" "+op.path] = op
	}
	live := map[string]any{}
	exercised := map[string]bool{}
	call := func(key string, overrides map[string]any) map[string]any {
		t.Helper()
		op, ok := byPath[key]
		if !ok {
			t.Fatalf("%s is not documented", key)
		}
		var got apiAnswer
		if _, example, ok := requestBody(op); ok {
			body := map[string]any{}
			for k, v := range example.(map[string]any) {
				body[k] = v
			}
			for k, v := range overrides {
				body[k] = v
			}
			got = apiCall(t, f, issued.Token, op.path, body)
		} else if op.method == "GET" {
			got = bearer(t, f, op.path, issued.Token)
		} else {
			got = apiCall(t, f, issued.Token, op.path, map[string]any{})
		}
		if got.status != http.StatusOK {
			t.Fatalf("%s: %d %s", key, got.status, got.raw)
		}
		var answer any
		if err := json.Unmarshal(got.raw, &answer); err != nil {
			t.Fatalf("%s: %v", key, err)
		}
		schema, err := responseSchema(doc, op)
		if err != nil {
			t.Fatal(err)
		}
		if err := validate(doc, schema, answer, key); err != nil {
			t.Fatalf("%v\n%s", err, got.raw)
		}
		exercised[key] = true
		object, _ := answer.(map[string]any)
		return object
	}
	call("GET /api/status", nil)
	call("GET /api/hosts", nil)
	session := call("POST /api/session", nil)["session_id"]
	ran := call("POST /api/run", map[string]any{"session": session})
	live["run_id"], live["req_id"] = ran["run_id"], ran["req_id"]
	call("POST /api/run/output", map[string]any{"run_id": live["run_id"], "offset": 0})
	call("POST /api/request/status", map[string]any{"req_id": live["req_id"]})
	gray := call("POST /api/run", map[string]any{"session": session, "command": "hostname"})
	approvalID := gray["responses"].([]any)[0].(map[string]any)["approval_id"]
	call("POST /api/approval/status", map[string]any{"approval_id": approvalID, "wait_ms": 0})
	call("POST /api/run/cancel", map[string]any{"run_id": live["run_id"]})
	call("GET /api/openapi.json", nil)
	for key := range byPath {
		if !exercised[key] {
			t.Errorf("%s was never exercised", key)
		}
	}
	// A refusal answers the documented error shape.
	refused := bearer(t, f, remote.PathTokenHosts, "agt_0123456789abcdef_"+strings.Repeat("A", 43))
	var answer any
	_ = json.Unmarshal(refused.raw, &answer)
	if err := validate(doc, map[string]any{"$ref": "#/components/schemas/Error"}, answer, "refusal"); err != nil || refused.status != http.StatusUnauthorized {
		t.Fatalf("refusal %d %s: %v", refused.status, refused.raw, err)
	}
}

// Each endpoint answers what its CLI counterpart prints for the same device
// state: hosts --json, status --json, approval status, session new.
func TestEndpointsAnswerLikeTheCLI(t *testing.T) {
	f, _ := execGateway(t)
	issued := activeTokenDevice(t, f)
	same := func(name string, got []byte, want any) {
		t.Helper()
		wantJSON, _ := json.Marshal(want)
		var a, b any
		_ = json.Unmarshal(got, &a)
		_ = json.Unmarshal(wantJSON, &b)
		if fmt.Sprint(a) != fmt.Sprint(b) {
			t.Fatalf("%s:\nAPI %s\nCLI %s", name, got, wantJSON)
		}
	}
	// hosts --json prints the public inventory of the pushed configuration.
	cfg, err := f.store.Config(issued.DeviceID)
	if err != nil {
		t.Fatal(err)
	}
	inv, _, err := remote.ParseManaged(cfg.InventoryYAML, cfg.PolicyYAML, nil)
	if err != nil {
		t.Fatal(err)
	}
	same("hosts", bearer(t, f, remote.PathTokenHosts, issued.Token).raw, inventory.NewResolver(inv).Public())

	// status --json prints the request's latest audit record of the device.
	ran := runOf(t, apiCall(t, f, issued.Token, remote.PathAPIRun, run("web-1", "uptime")))
	records, err := audit.NewStore(filepath.Join(f.dir, gateway.FileAudit)).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	var own []audit.Record
	for _, r := range records {
		if r.DeviceID == issued.DeviceID {
			own = append(own, r)
		}
	}
	want, ok := runner.RequestStatus(own, ran.ReqID)
	if !ok {
		t.Fatal("no audit record of the run")
	}
	same("request status", apiCall(t, f, issued.Token, remote.PathAPIRequestStatus, remote.RequestStatusRequest{ReqID: ran.ReqID}).raw, want)

	// approval status prints the device's request; a wait returns as soon as
	// an operator decides.
	gray := runOf(t, apiCall(t, f, issued.Token, remote.PathAPIRun, run("web-1", "hostname")))
	var response runner.Response
	if err := json.Unmarshal(gray.Responses[0], &response); err != nil || response.ApprovalID == "" {
		t.Fatalf("gray zone: %s", gray.Responses[0])
	}
	_, pending, err := gateway.ApprovalStatus(f.dir, issued.DeviceID, response.ApprovalID)
	if err != nil {
		t.Fatal(err)
	}
	same("approval status", apiCall(t, f, issued.Token, remote.PathAPIApprovalStatus, remote.APIApprovalStatusRequest{ApprovalID: response.ApprovalID, WaitMS: waitMS(0)}).raw, pending)
	go func() {
		time.Sleep(300 * time.Millisecond)
		_, _, _ = gateway.DecideApproval(f.dir, f.store, gateway.Decider{Operator: "local:alice"}, response.ApprovalID, approval.VerdictApproved, approval.ScopeSession)
	}()
	start := time.Now()
	decided := apiCall(t, f, issued.Token, remote.PathAPIApprovalStatus, remote.APIApprovalStatusRequest{ApprovalID: response.ApprovalID, WaitMS: waitMS(10000)})
	if took := time.Since(start); took > 5*time.Second {
		t.Fatalf("the wait ended %s after the decision", took)
	}
	_, approved, err := gateway.ApprovalStatus(f.dir, issued.DeviceID, response.ApprovalID)
	if err != nil || approved.Status != "approved" {
		t.Fatalf("decision: %+v %v", approved, err)
	}
	same("approval status after the decision", decided.raw, approved)

	// session new prints s_ and eight hex characters, fresh each time.
	first := apiCall(t, f, issued.Token, remote.PathAPISession, map[string]any{})
	second := apiCall(t, f, issued.Token, remote.PathAPISession, map[string]any{})
	var a, b remote.APISession
	_ = json.Unmarshal(first.raw, &a)
	_ = json.Unmarshal(second.raw, &b)
	if !regexp.MustCompile(`^s_[0-9a-f]{8}$`).MatchString(a.SessionID) || a.SessionID == b.SessionID {
		t.Fatalf("sessions %q, %q", a.SessionID, b.SessionID)
	}
}

// The validator refuses what the schemas forbid, so the document tests are
// not vacuous.
func TestTheSchemaValidatorRefusesViolations(t *testing.T) {
	doc := map[string]any{"components": map[string]any{"schemas": map[string]any{
		"Thing": map[string]any{
			"type": "object", "required": []any{"id"}, "additionalProperties": false,
			"properties": map[string]any{
				"id":    map[string]any{"type": "string"},
				"n":     map[string]any{"type": "integer"},
				"state": map[string]any{"type": "string", "enum": []any{"a", "b"}},
				"list":  map[string]any{"type": "array", "items": map[string]any{"type": "boolean"}},
				"opt":   map[string]any{"type": []any{"string", "null"}},
			},
		},
	}}}
	ref := map[string]any{"$ref": "#/components/schemas/Thing"}
	good := map[string]any{"id": "x", "n": 3.0, "state": "a", "list": []any{true}, "opt": nil}
	if err := validate(doc, ref, good, "good"); err != nil {
		t.Fatalf("a valid value: %v", err)
	}
	for name, bad := range map[string]any{
		"missing required": map[string]any{"n": 1.0},
		"wrong type":       map[string]any{"id": 1.0},
		"not an integer":   map[string]any{"id": "x", "n": 1.5},
		"outside enum":     map[string]any{"id": "x", "state": "c"},
		"bad item":         map[string]any{"id": "x", "list": []any{"yes"}},
		"unknown field":    map[string]any{"id": "x", "extra": true},
		"not an object":    "x",
	} {
		if validate(doc, ref, bad, name) == nil {
			t.Errorf("%s passed", name)
		}
	}
	if validate(doc, map[string]any{"$ref": "#/components/schemas/Missing"}, good, "ref") == nil {
		t.Error("an unresolved $ref passed")
	}
}
