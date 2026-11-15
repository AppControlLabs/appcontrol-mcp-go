package tools

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Register adds every spec to s as a read-only tool answered by b. Arguments
// are validated against the spec's schema before Call runs; a validation or
// call failure reaches the client as an IsError result, never a protocol error.
func Register(s *mcp.Server, b Backend, specs []Spec) {
	for _, spec := range specs {
		resolved, err := spec.Input.Resolve(nil)
		if err != nil {
			panic(fmt.Errorf("tools: %s: %v", spec.Name, err))
		}
		call := spec.Call
		s.AddTool(&mcp.Tool{
			Name:        spec.Name,
			Description: spec.Description,
			InputSchema: spec.Input,
			Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true},
		}, func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			args := req.Params.Arguments
			if err := validate(resolved, args); err != nil {
				return errorResult(fmt.Errorf("validating arguments: %v", err)), nil
			}
			body, err := call(ctx, b, args)
			if err != nil {
				return errorResult(err), nil
			}
			return textResult(body), nil
		})
	}
}

func validate(rs *jsonschema.Resolved, args json.RawMessage) error {
	v := map[string]any{}
	if len(args) > 0 {
		if err := json.Unmarshal(args, &v); err != nil {
			return err
		}
		if v == nil {
			v = map[string]any{}
		}
	}
	return rs.Validate(v)
}

// textResult carries the API body as text and, when it parses, as structured content too.
func textResult(body string) *mcp.CallToolResult {
	res := &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: body}}}
	var structured any
	if json.Unmarshal([]byte(body), &structured) == nil && structured != nil {
		res.StructuredContent = structured
	}
	return res
}

func errorResult(err error) *mcp.CallToolResult {
	var res mcp.CallToolResult
	res.SetError(err)
	return &res
}
