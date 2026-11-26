package tools

import (
	"context"
	"encoding/json"
	"net/url"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type fakeBackend struct {
	path   string
	params url.Values
	body   string
	err    error
}

func (f *fakeBackend) Get(_ context.Context, path string, params url.Values) (string, error) {
	f.path = path
	f.params = params
	if f.err != nil {
		return "", f.err
	}
	return f.body, nil
}

var wantOrder = []string{
	"list_binaries", "get_binary", "list_processes", "list_publishers", "list_rules",
	"query_history", "get_stats", "get_monitoring", "get_hardware", "list_services",
}

func spec(t *testing.T, name string) Spec {
	t.Helper()
	for _, s := range Specs() {
		if s.Name == name {
			return s
		}
	}
	t.Fatalf("no spec %q", name)
	return Spec{}
}

// call runs the named spec against a recording backend and returns the recording.
func call(t *testing.T, name, args string) *fakeBackend {
	t.Helper()
	b := &fakeBackend{body: `{"ok":true}`}
	s := spec(t, name)
	if _, err := s.Call(context.Background(), b, json.RawMessage(args)); err != nil {
		t.Fatalf("%s(%s): %v", name, args, err)
	}
	return b
}

func expectParams(t *testing.T, got url.Values, want map[string]string) {
	t.Helper()
	for k, v := range want {
		if g := got.Get(k); g != v {
			t.Errorf("param %s = %q, want %q", k, g, v)
		}
	}
	for k := range got {
		if _, ok := want[k]; !ok {
			t.Errorf("unexpected param %s=%q", k, got.Get(k))
		}
	}
}

func TestSpecsOrder(t *testing.T) {
	specs := Specs()
	if len(specs) != len(wantOrder) {
		t.Fatalf("Specs() has %d entries, want %d", len(specs), len(wantOrder))
	}
	for i, s := range specs {
		if s.Name != wantOrder[i] {
			t.Errorf("Specs()[%d] = %q, want %q", i, s.Name, wantOrder[i])
		}
		if s.Description == "" || s.Input == nil || s.Call == nil {
			t.Errorf("%s: incomplete spec", s.Name)
		}
	}
}

func TestSchemasHaveNoMachineProperty(t *testing.T) {
	for _, s := range Specs() {
		if s.Input.Type != "object" {
			t.Errorf("%s: schema type %q, want object", s.Name, s.Input.Type)
		}
		if _, ok := s.Input.Properties["machine"]; ok {
			t.Errorf("%s: schema has a machine property", s.Name)
		}
	}
}

func TestListBinaries(t *testing.T) {
	b := call(t, "list_binaries", `{"limit":500,"unsigned_only":true,"running_only":false,"publisher_id":7,"first_seen_after":1710806400000,"path_contains":"Temp"}`)
	if b.path != "/api/v1/binaries" {
		t.Errorf("path = %q", b.path)
	}
	expectParams(t, b.params, map[string]string{
		"offset": "0", "limit": "200", "unsigned_only": "1", "publisher_id": "7",
		"first_seen_after": "1710806400000", "path_contains": "Temp",
	})

	b = call(t, "list_binaries", `{}`)
	expectParams(t, b.params, map[string]string{"offset": "0", "limit": "100"})
}

func TestGetBinary(t *testing.T) {
	b := call(t, "get_binary", `{"binary_id":42}`)
	if b.path != "/api/v1/binaries/42" {
		t.Errorf("path = %q", b.path)
	}
	if len(b.params) != 0 {
		t.Errorf("params = %v, want none", b.params)
	}

	b = call(t, "get_binary", `{"binary_ids":"42,55,103"}`)
	if b.path != "/api/v1/binaries" {
		t.Errorf("path = %q", b.path)
	}
	expectParams(t, b.params, map[string]string{"ids": "42,55,103"})

	s := spec(t, "get_binary")
	if _, err := s.Call(context.Background(), &fakeBackend{}, json.RawMessage(`{}`)); err == nil {
		t.Error("get_binary with no id: want an error")
	}
}

func TestListProcesses(t *testing.T) {
	b := call(t, "list_processes", `{"limit":10,"offset":20,"fields":"name,services","search":"svc","username":"SYSTEM","binary_id":3,"elevated_only":true,"flags":"Service","exclude_flags":"System"}`)
	if b.path != "/api/v1/processes" {
		t.Errorf("path = %q", b.path)
	}
	expectParams(t, b.params, map[string]string{
		"offset": "20", "limit": "10", "fields": "name,services", "search": "svc", "username": "SYSTEM",
		"binary_id": "3", "elevated_only": "1", "flags": "Service", "exclude_flags": "System",
	})
}

func TestListPublishers(t *testing.T) {
	b := call(t, "list_publishers", `{"limit":0,"offset":5}`)
	if b.path != "/api/v1/publishers" {
		t.Errorf("path = %q", b.path)
	}
	expectParams(t, b.params, map[string]string{"offset": "5", "limit": "100"})
}

func TestListRules(t *testing.T) {
	b := call(t, "list_rules", `{"limit":201}`)
	if b.path != "/api/v1/rules" {
		t.Errorf("path = %q", b.path)
	}
	expectParams(t, b.params, map[string]string{"offset": "0", "limit": "200"})
}

func TestQueryHistory(t *testing.T) {
	b := call(t, "query_history", `{"start_time":1,"end_time":2,"event_type":"NewBinarySeen,BlockProcess","binary_ids":[1,2,3],"publisher_ids":[9],"unsigned_only":true,"before_id":77,"limit":1000}`)
	if b.path != "/api/v1/history" {
		t.Errorf("path = %q", b.path)
	}
	expectParams(t, b.params, map[string]string{
		"limit": "200", "start_time": "1", "end_time": "2", "event_type": "NewBinarySeen,BlockProcess",
		"binary_ids": "1,2,3", "publisher_ids": "9", "unsigned_only": "1", "before_id": "77",
	})

	b = call(t, "query_history", `{}`)
	expectParams(t, b.params, map[string]string{"limit": "100"})
}

func TestGetStats(t *testing.T) {
	for _, args := range []string{"", "null", "{}"} {
		b := call(t, "get_stats", args)
		if b.path != "/api/v1/stats" || len(b.params) != 0 {
			t.Errorf("args %q: path %q params %v", args, b.path, b.params)
		}
	}
}

func TestGetMonitoring(t *testing.T) {
	b := call(t, "get_monitoring", `{"start_time":10,"end_time":20,"resolution":60,"limit":5000,"type":"binary","binary_ids":[4,5],"top_n":3,"sort_by":"power","min_value":100}`)
	if b.path != "/api/v1/monitoring" {
		t.Errorf("path = %q", b.path)
	}
	expectParams(t, b.params, map[string]string{
		"start_time": "10", "end_time": "20", "resolution": "60", "limit": "1000", "type": "binary",
		"binary_ids": "4,5", "top_n": "3", "sort_by": "power", "min_value": "100",
	})

	b = call(t, "get_monitoring", `{}`)
	expectParams(t, b.params, map[string]string{})
}

func TestGetHardware(t *testing.T) {
	for _, args := range []string{"", "null", "{}"} {
		b := call(t, "get_hardware", args)
		if b.path != "/api/v1/hardware" || len(b.params) != 0 {
			t.Errorf("args %q: path %q params %v", args, b.path, b.params)
		}
	}
}

func TestListServices(t *testing.T) {
	b := call(t, "list_services", `{"search":"update","running_only":true,"drivers_only":true,"start_type":"Auto","limit":50,"offset":2}`)
	if b.path != "/api/v1/services" {
		t.Errorf("path = %q", b.path)
	}
	expectParams(t, b.params, map[string]string{
		"offset": "2", "limit": "50", "search": "update", "running_only": "1", "drivers_only": "1", "start_type": "Auto",
	})
}

// connect registers the specs on a server and returns a client session to it.
func connect(t *testing.T, b Backend) *mcp.ClientSession {
	t.Helper()
	ctx := context.Background()
	server := mcp.NewServer(&mcp.Implementation{Name: "test", Version: "0"}, nil)
	Register(server, b, Specs())
	st, ct := mcp.NewInMemoryTransports()
	ss, err := server.Connect(ctx, st, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ss.Close() })
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "client", Version: "0"}, nil).Connect(ctx, ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cs.Close() })
	return cs
}

func TestRegisterReadOnly(t *testing.T) {
	cs := connect(t, &fakeBackend{body: "{}"})
	res, err := cs.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Tools) != len(wantOrder) {
		t.Fatalf("%d tools registered, want %d", len(res.Tools), len(wantOrder))
	}
	seen := map[string]bool{}
	for _, tool := range res.Tools {
		seen[tool.Name] = true
		if tool.Annotations == nil || !tool.Annotations.ReadOnlyHint {
			t.Errorf("%s: missing ReadOnlyHint", tool.Name)
		}
		if tool.InputSchema == nil {
			t.Errorf("%s: no input schema", tool.Name)
		}
	}
	for _, name := range wantOrder {
		if !seen[name] {
			t.Errorf("%s not registered", name)
		}
	}
}

func TestRegisterCallResults(t *testing.T) {
	b := &fakeBackend{body: `{"ok":true,"data":[]}`}
	cs := connect(t, b)
	ctx := context.Background()

	res, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "list_rules", Arguments: map[string]any{"limit": 5}})
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		t.Fatalf("unexpected error result: %v", res.Content)
	}
	if text, ok := res.Content[0].(*mcp.TextContent); !ok || text.Text != b.body {
		t.Errorf("content = %#v, want the body as text", res.Content[0])
	}
	if res.StructuredContent == nil {
		t.Error("no structured content")
	}
	if b.params.Get("limit") != "5" {
		t.Errorf("limit = %q, want 5", b.params.Get("limit"))
	}

	// No arguments at all is a valid call for a no-input tool.
	res, err = cs.CallTool(ctx, &mcp.CallToolParams{Name: "get_stats"})
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError || b.path != "/api/v1/stats" {
		t.Errorf("get_stats: IsError=%v path=%q", res.IsError, b.path)
	}

	// A backend failure is a tool error, not a protocol error.
	b.err = ErrUnavailable
	res, err = cs.CallTool(ctx, &mcp.CallToolParams{Name: "get_hardware"})
	if err != nil {
		t.Fatal(err)
	}
	if !res.IsError {
		t.Fatal("backend error: want IsError")
	}
	if text, ok := res.Content[0].(*mcp.TextContent); !ok || !strings.Contains(text.Text, ErrUnavailable.Error()) {
		t.Errorf("error content = %#v", res.Content[0])
	}

	// Arguments of the wrong type are rejected before the backend is asked.
	b.err = nil
	b.path = ""
	res, err = cs.CallTool(ctx, &mcp.CallToolParams{Name: "list_rules", Arguments: map[string]any{"limit": "five"}})
	if err != nil {
		t.Fatal(err)
	}
	if !res.IsError || b.path != "" {
		t.Errorf("bad argument: IsError=%v path=%q", res.IsError, b.path)
	}
}

func TestMonitoringArgumentBounds(t *testing.T) {
	b := &fakeBackend{body: `{"ok":true}`}
	cs := connect(t, b)
	ctx := context.Background()

	for _, args := range []map[string]any{
		{"resolution": -1},
		{"resolution": maxResolution + 1},
		{"type": "NotARealType"},
		{"type": "binary", "sort_by": "bogus"},
	} {
		b.path = ""
		res, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "get_monitoring", Arguments: args})
		if err != nil {
			t.Fatal(err)
		}
		if !res.IsError || b.path != "" {
			t.Errorf("%v: IsError=%v path=%q, want refused before the backend", args, res.IsError, b.path)
		}
	}

	for _, args := range []map[string]any{
		{"resolution": 0},
		{"resolution": maxResolution, "type": "system"},
		{"type": "binary", "sort_by": "power"},
	} {
		b.path = ""
		res, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "get_monitoring", Arguments: args})
		if err != nil {
			t.Fatal(err)
		}
		if res.IsError || b.path != "/api/v1/monitoring" {
			t.Errorf("%v: IsError=%v path=%q, want accepted", args, res.IsError, b.path)
		}
	}
}
