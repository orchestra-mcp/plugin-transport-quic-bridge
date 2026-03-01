package internal

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	pluginv1 "github.com/orchestra-mcp/gen-go/orchestra/plugin/v1"
	"github.com/orchestra-mcp/sdk-go/protocol"
	"google.golang.org/protobuf/types/known/structpb"
)

// mockSender implements the Sender interface for testing without QUIC.
type mockSender struct {
	sendFunc func(ctx context.Context, req *pluginv1.PluginRequest) (*pluginv1.PluginResponse, error)
}

func (m *mockSender) Send(ctx context.Context, req *pluginv1.PluginRequest) (*pluginv1.PluginResponse, error) {
	if m.sendFunc != nil {
		return m.sendFunc(ctx, req)
	}
	return nil, fmt.Errorf("mockSender: no sendFunc configured")
}

// dispatchRequest is a test helper that dispatches a JSON-RPC request through
// the bridge and returns the response.
func dispatchRequest(t *testing.T, sender Sender, apiKey string, req *protocol.JSONRPCRequest) *protocol.JSONRPCResponse {
	t.Helper()
	bridge := NewBridge(sender, apiKey)
	return bridge.dispatch(context.Background(), req)
}

// dispatchJSON is a test helper that dispatches a raw JSON string as a JSON-RPC
// request through the bridge and returns the response.
func dispatchJSON(t *testing.T, sender Sender, apiKey string, reqJSON string) *protocol.JSONRPCResponse {
	t.Helper()
	var req protocol.JSONRPCRequest
	if err := json.Unmarshal([]byte(reqJSON), &req); err != nil {
		t.Fatalf("parse request JSON: %v", err)
	}
	return dispatchRequest(t, sender, apiKey, &req)
}

// --- Framing tests ---

func TestFramingRoundTrip(t *testing.T) {
	original := &protocol.JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      float64(1),
		Method:  "ping",
	}

	var buf bytes.Buffer
	if err := writeJSONFrame(&buf, original); err != nil {
		t.Fatalf("writeJSONFrame: %v", err)
	}

	var decoded protocol.JSONRPCRequest
	if err := readJSONFrame(&buf, &decoded); err != nil {
		t.Fatalf("readJSONFrame: %v", err)
	}

	if decoded.JSONRPC != "2.0" {
		t.Errorf("jsonrpc: got %q, want %q", decoded.JSONRPC, "2.0")
	}
	if decoded.Method != "ping" {
		t.Errorf("method: got %q, want %q", decoded.Method, "ping")
	}
}

func TestFramingResponseRoundTrip(t *testing.T) {
	original := &protocol.JSONRPCResponse{
		JSONRPC: "2.0",
		ID:      float64(42),
		Result:  map[string]any{"status": "ok"},
	}

	var buf bytes.Buffer
	if err := writeJSONFrame(&buf, original); err != nil {
		t.Fatalf("writeJSONFrame: %v", err)
	}

	var decoded protocol.JSONRPCResponse
	if err := readJSONFrame(&buf, &decoded); err != nil {
		t.Fatalf("readJSONFrame: %v", err)
	}

	if decoded.JSONRPC != "2.0" {
		t.Errorf("jsonrpc: got %q, want %q", decoded.JSONRPC, "2.0")
	}
}

func TestFramingEmptyReader(t *testing.T) {
	var buf bytes.Buffer
	var decoded protocol.JSONRPCRequest
	err := readJSONFrame(&buf, &decoded)
	if err == nil {
		t.Fatal("expected error reading from empty buffer")
	}
}

// --- Authentication tests ---

func TestAuthenticateSuccess(t *testing.T) {
	bridge := NewBridge(&mockSender{}, "secret-key-123")

	reqJSON := `{"jsonrpc":"2.0","id":1,"method":"authenticate","params":{"api_key":"secret-key-123"}}`
	var req protocol.JSONRPCRequest
	if err := json.Unmarshal([]byte(reqJSON), &req); err != nil {
		t.Fatalf("parse: %v", err)
	}

	resp := bridge.handleAuthenticate(&req)
	if resp.Error != nil {
		t.Fatalf("unexpected error: %+v", resp.Error)
	}

	resultBytes, _ := json.Marshal(resp.Result)
	var result map[string]any
	if err := json.Unmarshal(resultBytes, &result); err != nil {
		t.Fatalf("unmarshal result: %v", err)
	}
	if result["authenticated"] != true {
		t.Errorf("expected authenticated=true, got %v", result["authenticated"])
	}
}

func TestAuthenticateWrongKey(t *testing.T) {
	bridge := NewBridge(&mockSender{}, "correct-key")

	reqJSON := `{"jsonrpc":"2.0","id":1,"method":"authenticate","params":{"api_key":"wrong-key"}}`
	var req protocol.JSONRPCRequest
	json.Unmarshal([]byte(reqJSON), &req)

	resp := bridge.handleAuthenticate(&req)
	if resp.Error == nil {
		t.Fatal("expected authentication error")
	}
	if resp.Error.Code != protocol.InvalidRequest {
		t.Errorf("error code: got %d, want %d", resp.Error.Code, protocol.InvalidRequest)
	}
	if !strings.Contains(resp.Error.Message, "invalid API key") {
		t.Errorf("error message should mention invalid API key, got: %s", resp.Error.Message)
	}
}

func TestAuthenticateMissingKey(t *testing.T) {
	bridge := NewBridge(&mockSender{}, "secret")

	reqJSON := `{"jsonrpc":"2.0","id":1,"method":"authenticate","params":{}}`
	var req protocol.JSONRPCRequest
	json.Unmarshal([]byte(reqJSON), &req)

	resp := bridge.handleAuthenticate(&req)
	if resp.Error == nil {
		t.Fatal("expected error for missing API key")
	}
	if resp.Error.Code != protocol.InvalidParams {
		t.Errorf("error code: got %d, want %d", resp.Error.Code, protocol.InvalidParams)
	}
}

func TestAuthenticateInvalidParams(t *testing.T) {
	bridge := NewBridge(&mockSender{}, "secret")

	req := &protocol.JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      float64(1),
		Method:  "authenticate",
		Params:  json.RawMessage(`"not an object"`),
	}

	resp := bridge.handleAuthenticate(req)
	if resp.Error == nil {
		t.Fatal("expected error for invalid params")
	}
	if resp.Error.Code != protocol.InvalidParams {
		t.Errorf("error code: got %d, want %d", resp.Error.Code, protocol.InvalidParams)
	}
}

// --- Initialize tests ---

func TestInitialize(t *testing.T) {
	resp := dispatchJSON(t, &mockSender{}, "", `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`)

	if resp.JSONRPC != "2.0" {
		t.Errorf("jsonrpc: got %q, want %q", resp.JSONRPC, "2.0")
	}
	if resp.Error != nil {
		t.Fatalf("unexpected error: %+v", resp.Error)
	}

	resultBytes, _ := json.Marshal(resp.Result)
	var initResult protocol.MCPInitializeResult
	if err := json.Unmarshal(resultBytes, &initResult); err != nil {
		t.Fatalf("unmarshal init result: %v", err)
	}

	if initResult.ProtocolVersion != "2024-11-05" {
		t.Errorf("protocolVersion: got %q, want %q", initResult.ProtocolVersion, "2024-11-05")
	}
	if initResult.ServerInfo.Name != "orchestra" {
		t.Errorf("serverInfo.name: got %q, want %q", initResult.ServerInfo.Name, "orchestra")
	}
	if initResult.Capabilities.Tools == nil {
		t.Error("expected capabilities.tools to be set")
	}
	if initResult.Capabilities.Prompts == nil {
		t.Error("expected capabilities.prompts to be set")
	}
}

// --- Ping tests ---

func TestPing(t *testing.T) {
	resp := dispatchJSON(t, &mockSender{}, "", `{"jsonrpc":"2.0","id":42,"method":"ping"}`)

	if resp.Error != nil {
		t.Fatalf("unexpected error: %+v", resp.Error)
	}
	resultBytes, _ := json.Marshal(resp.Result)
	if string(resultBytes) != "{}" {
		t.Errorf("ping result: got %s, want {}", string(resultBytes))
	}
}

// --- Tools/list tests ---

func TestToolsList(t *testing.T) {
	schema, _ := structpb.NewStruct(map[string]any{
		"type": "object",
		"properties": map[string]any{
			"project_id": map[string]any{"type": "string"},
		},
	})

	sender := &mockSender{
		sendFunc: func(ctx context.Context, req *pluginv1.PluginRequest) (*pluginv1.PluginResponse, error) {
			if req.GetListTools() == nil {
				t.Error("expected ListTools request")
			}
			// Verify the request ID prefix.
			if !strings.HasPrefix(req.RequestId, "quic-lt-") {
				t.Errorf("request ID should have quic-lt- prefix, got: %s", req.RequestId)
			}
			return &pluginv1.PluginResponse{
				RequestId: req.RequestId,
				Response: &pluginv1.PluginResponse_ListTools{
					ListTools: &pluginv1.ListToolsResponse{
						Tools: []*pluginv1.ToolDefinition{
							{
								Name:        "create_feature",
								Description: "Create a new feature",
								InputSchema: schema,
							},
						},
					},
				},
			}, nil
		},
	}

	resp := dispatchJSON(t, sender, "", `{"jsonrpc":"2.0","id":2,"method":"tools/list"}`)

	if resp.Error != nil {
		t.Fatalf("unexpected error: %+v", resp.Error)
	}

	resultBytes, _ := json.Marshal(resp.Result)
	var listResult toolsListResult
	if err := json.Unmarshal(resultBytes, &listResult); err != nil {
		t.Fatalf("unmarshal tools list: %v", err)
	}

	if len(listResult.Tools) != 1 {
		t.Fatalf("expected 1 tool, got %d", len(listResult.Tools))
	}
	if listResult.Tools[0].Name != "create_feature" {
		t.Errorf("tool name: got %q, want %q", listResult.Tools[0].Name, "create_feature")
	}
}

func TestToolsListNetworkError(t *testing.T) {
	sender := &mockSender{
		sendFunc: func(ctx context.Context, req *pluginv1.PluginRequest) (*pluginv1.PluginResponse, error) {
			return nil, fmt.Errorf("connection timeout")
		},
	}

	resp := dispatchJSON(t, sender, "", `{"jsonrpc":"2.0","id":7,"method":"tools/list"}`)

	if resp.Error == nil {
		t.Fatal("expected error for network failure")
	}
	if resp.Error.Code != protocol.InternalError {
		t.Errorf("error code: got %d, want %d", resp.Error.Code, protocol.InternalError)
	}
}

// --- Tools/call tests ---

func TestToolsCall(t *testing.T) {
	sender := &mockSender{
		sendFunc: func(ctx context.Context, req *pluginv1.PluginRequest) (*pluginv1.PluginResponse, error) {
			tc := req.GetToolCall()
			if tc == nil {
				t.Error("expected ToolCall request")
				return nil, fmt.Errorf("expected ToolCall request")
			}
			if tc.ToolName != "create_feature" {
				t.Errorf("tool name: got %q, want %q", tc.ToolName, "create_feature")
			}
			if tc.CallerPlugin != "transport.quic-bridge" {
				t.Errorf("caller_plugin: got %q, want %q", tc.CallerPlugin, "transport.quic-bridge")
			}
			if !strings.HasPrefix(req.RequestId, "quic-tc-") {
				t.Errorf("request ID should have quic-tc- prefix, got: %s", req.RequestId)
			}

			if tc.Arguments == nil {
				t.Error("expected arguments to be set")
			} else {
				pid := tc.Arguments.GetFields()["project_id"].GetStringValue()
				if pid != "my-project" {
					t.Errorf("argument project_id: got %q, want %q", pid, "my-project")
				}
			}

			result, _ := structpb.NewStruct(map[string]any{
				"text": "Created feature FEAT-ABC in project my-project",
			})
			return &pluginv1.PluginResponse{
				RequestId: req.RequestId,
				Response: &pluginv1.PluginResponse_ToolCall{
					ToolCall: &pluginv1.ToolResponse{
						Success: true,
						Result:  result,
					},
				},
			}, nil
		},
	}

	resp := dispatchJSON(t, sender, "", `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"create_feature","arguments":{"project_id":"my-project","title":"Add login"}}}`)

	if resp.Error != nil {
		t.Fatalf("unexpected error: %+v", resp.Error)
	}

	resultBytes, _ := json.Marshal(resp.Result)
	var mcpResult protocol.MCPToolResult
	if err := json.Unmarshal(resultBytes, &mcpResult); err != nil {
		t.Fatalf("unmarshal tool result: %v", err)
	}

	if mcpResult.IsError {
		t.Error("expected isError=false")
	}
	if len(mcpResult.Content) != 1 {
		t.Fatalf("expected 1 content block, got %d", len(mcpResult.Content))
	}
	if mcpResult.Content[0].Text != "Created feature FEAT-ABC in project my-project" {
		t.Errorf("content text: got %q", mcpResult.Content[0].Text)
	}
}

func TestToolsCallError(t *testing.T) {
	sender := &mockSender{
		sendFunc: func(ctx context.Context, req *pluginv1.PluginRequest) (*pluginv1.PluginResponse, error) {
			return &pluginv1.PluginResponse{
				RequestId: req.RequestId,
				Response: &pluginv1.PluginResponse_ToolCall{
					ToolCall: &pluginv1.ToolResponse{
						Success:      false,
						ErrorCode:    "tool_not_found",
						ErrorMessage: `tool "nonexistent" not found`,
					},
				},
			}, nil
		},
	}

	resp := dispatchJSON(t, sender, "", `{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"nonexistent","arguments":{}}}`)

	if resp.Error != nil {
		t.Fatalf("unexpected JSON-RPC error: %+v", resp.Error)
	}

	resultBytes, _ := json.Marshal(resp.Result)
	var mcpResult protocol.MCPToolResult
	if err := json.Unmarshal(resultBytes, &mcpResult); err != nil {
		t.Fatalf("unmarshal tool result: %v", err)
	}

	if !mcpResult.IsError {
		t.Error("expected isError=true")
	}
	if mcpResult.Content[0].Text != `tool "nonexistent" not found` {
		t.Errorf("error text: got %q", mcpResult.Content[0].Text)
	}
}

func TestToolsCallMissingName(t *testing.T) {
	resp := dispatchJSON(t, &mockSender{}, "", `{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"arguments":{}}}`)

	if resp.Error == nil {
		t.Fatal("expected error for missing tool name")
	}
	if resp.Error.Code != protocol.InvalidParams {
		t.Errorf("error code: got %d, want %d", resp.Error.Code, protocol.InvalidParams)
	}
	if !strings.Contains(resp.Error.Message, "name") {
		t.Errorf("error message should mention 'name', got: %s", resp.Error.Message)
	}
}

func TestToolsCallNetworkError(t *testing.T) {
	sender := &mockSender{
		sendFunc: func(ctx context.Context, req *pluginv1.PluginRequest) (*pluginv1.PluginResponse, error) {
			return nil, fmt.Errorf("connection refused")
		},
	}

	resp := dispatchJSON(t, sender, "", `{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"create_feature","arguments":{}}}`)

	if resp.Error == nil {
		t.Fatal("expected JSON-RPC error for network failure")
	}
	if resp.Error.Code != protocol.InternalError {
		t.Errorf("error code: got %d, want %d", resp.Error.Code, protocol.InternalError)
	}
	if !strings.Contains(resp.Error.Message, "connection refused") {
		t.Errorf("error message should contain 'connection refused', got: %s", resp.Error.Message)
	}
}

// --- Prompts/list tests ---

func TestPromptsList(t *testing.T) {
	sender := &mockSender{
		sendFunc: func(ctx context.Context, req *pluginv1.PluginRequest) (*pluginv1.PluginResponse, error) {
			if req.GetListPrompts() == nil {
				t.Error("expected ListPrompts request")
			}
			if !strings.HasPrefix(req.RequestId, "quic-lp-") {
				t.Errorf("request ID should have quic-lp- prefix, got: %s", req.RequestId)
			}
			return &pluginv1.PluginResponse{
				RequestId: req.RequestId,
				Response: &pluginv1.PluginResponse_ListPrompts{
					ListPrompts: &pluginv1.ListPromptsResponse{
						Prompts: []*pluginv1.PromptDefinition{
							{
								Name:        "setup-project",
								Description: "Guide setting up a new project",
								Arguments: []*pluginv1.PromptArgument{
									{Name: "project_name", Description: "Name of the project", Required: true},
								},
							},
						},
					},
				},
			}, nil
		},
	}

	resp := dispatchJSON(t, sender, "", `{"jsonrpc":"2.0","id":2,"method":"prompts/list"}`)

	if resp.Error != nil {
		t.Fatalf("unexpected error: %+v", resp.Error)
	}

	resultBytes, _ := json.Marshal(resp.Result)
	var listResult promptsListResult
	if err := json.Unmarshal(resultBytes, &listResult); err != nil {
		t.Fatalf("unmarshal prompts list: %v", err)
	}

	if len(listResult.Prompts) != 1 {
		t.Fatalf("expected 1 prompt, got %d", len(listResult.Prompts))
	}
	if listResult.Prompts[0].Name != "setup-project" {
		t.Errorf("prompt name: got %q", listResult.Prompts[0].Name)
	}
}

func TestPromptsListNetworkError(t *testing.T) {
	sender := &mockSender{
		sendFunc: func(ctx context.Context, req *pluginv1.PluginRequest) (*pluginv1.PluginResponse, error) {
			return nil, fmt.Errorf("connection timeout")
		},
	}

	resp := dispatchJSON(t, sender, "", `{"jsonrpc":"2.0","id":7,"method":"prompts/list"}`)

	if resp.Error == nil {
		t.Fatal("expected error for network failure")
	}
	if resp.Error.Code != protocol.InternalError {
		t.Errorf("error code: got %d, want %d", resp.Error.Code, protocol.InternalError)
	}
}

// --- Prompts/get tests ---

func TestPromptsGet(t *testing.T) {
	sender := &mockSender{
		sendFunc: func(ctx context.Context, req *pluginv1.PluginRequest) (*pluginv1.PluginResponse, error) {
			pg := req.GetPromptGet()
			if pg == nil {
				t.Error("expected PromptGet request")
				return nil, fmt.Errorf("expected PromptGet request")
			}
			if pg.PromptName != "setup-project" {
				t.Errorf("prompt name: got %q", pg.PromptName)
			}
			if pg.Arguments["project_name"] != "demo" {
				t.Errorf("argument project_name: got %q", pg.Arguments["project_name"])
			}
			if !strings.HasPrefix(req.RequestId, "quic-pg-") {
				t.Errorf("request ID should have quic-pg- prefix, got: %s", req.RequestId)
			}

			return &pluginv1.PluginResponse{
				RequestId: req.RequestId,
				Response: &pluginv1.PluginResponse_PromptGet{
					PromptGet: &pluginv1.PromptGetResponse{
						Description: "Set up a new project with recommended packs",
						Messages: []*pluginv1.PromptMessage{
							{
								Role: "user",
								Content: &pluginv1.ContentBlock{
									Type: "text",
									Text: "Set up project 'demo'.",
								},
							},
						},
					},
				},
			}, nil
		},
	}

	resp := dispatchJSON(t, sender, "", `{"jsonrpc":"2.0","id":3,"method":"prompts/get","params":{"name":"setup-project","arguments":{"project_name":"demo"}}}`)

	if resp.Error != nil {
		t.Fatalf("unexpected error: %+v", resp.Error)
	}

	resultBytes, _ := json.Marshal(resp.Result)
	var promptResult protocol.MCPPromptResult
	if err := json.Unmarshal(resultBytes, &promptResult); err != nil {
		t.Fatalf("unmarshal prompt result: %v", err)
	}

	if promptResult.Description != "Set up a new project with recommended packs" {
		t.Errorf("description: got %q", promptResult.Description)
	}
	if len(promptResult.Messages) != 1 {
		t.Fatalf("expected 1 message, got %d", len(promptResult.Messages))
	}
	if promptResult.Messages[0].Content.Text != "Set up project 'demo'." {
		t.Errorf("content text: got %q", promptResult.Messages[0].Content.Text)
	}
}

func TestPromptsGetMissingName(t *testing.T) {
	resp := dispatchJSON(t, &mockSender{}, "", `{"jsonrpc":"2.0","id":6,"method":"prompts/get","params":{"arguments":{}}}`)

	if resp.Error == nil {
		t.Fatal("expected error for missing prompt name")
	}
	if resp.Error.Code != protocol.InvalidParams {
		t.Errorf("error code: got %d, want %d", resp.Error.Code, protocol.InvalidParams)
	}
}

// --- Method not found ---

func TestMethodNotFound(t *testing.T) {
	resp := dispatchJSON(t, &mockSender{}, "", `{"jsonrpc":"2.0","id":10,"method":"unknown/method"}`)

	if resp.Error == nil {
		t.Fatal("expected error for unknown method")
	}
	if resp.Error.Code != protocol.MethodNotFound {
		t.Errorf("error code: got %d, want %d", resp.Error.Code, protocol.MethodNotFound)
	}
	if !strings.Contains(resp.Error.Message, "unknown/method") {
		t.Errorf("error message should mention the method, got: %s", resp.Error.Message)
	}
}

// --- Notification ---

func TestNotification(t *testing.T) {
	var req protocol.JSONRPCRequest
	json.Unmarshal([]byte(`{"jsonrpc":"2.0","method":"notifications/initialized"}`), &req)

	bridge := NewBridge(&mockSender{}, "")
	resp := bridge.dispatch(context.Background(), &req)

	if resp != nil {
		t.Errorf("expected nil response for notification, got: %+v", resp)
	}
}

// --- Translator tests ---

func TestStructToMap(t *testing.T) {
	s, _ := structpb.NewStruct(map[string]any{
		"name":   "test",
		"count":  42.0,
		"active": true,
		"tags":   []any{"a", "b"},
		"nested": map[string]any{"key": "val"},
	})

	m := StructToMap(s)

	if m["name"] != "test" {
		t.Errorf("name: got %v", m["name"])
	}
	if m["count"] != 42.0 {
		t.Errorf("count: got %v", m["count"])
	}
	if m["active"] != true {
		t.Errorf("active: got %v", m["active"])
	}
	tags, ok := m["tags"].([]any)
	if !ok || len(tags) != 2 {
		t.Errorf("tags: got %v", m["tags"])
	}
	nested, ok := m["nested"].(map[string]any)
	if !ok || nested["key"] != "val" {
		t.Errorf("nested: got %v", m["nested"])
	}
}

func TestStructToMapNil(t *testing.T) {
	m := StructToMap(nil)
	if m != nil {
		t.Errorf("expected nil, got %v", m)
	}
}

func TestMapToStruct(t *testing.T) {
	m := map[string]any{
		"type": "object",
		"properties": map[string]any{
			"id": map[string]any{"type": "string"},
		},
	}

	s, err := MapToStruct(m)
	if err != nil {
		t.Fatalf("MapToStruct: %v", err)
	}

	m2 := StructToMap(s)
	if m2["type"] != "object" {
		t.Errorf("type: got %v", m2["type"])
	}
}

func TestToolDefinitionToMCP(t *testing.T) {
	schema, _ := structpb.NewStruct(map[string]any{
		"type": "object",
		"properties": map[string]any{
			"id": map[string]any{"type": "string"},
		},
	})

	td := &pluginv1.ToolDefinition{
		Name:        "my_tool",
		Description: "Does things",
		InputSchema: schema,
	}

	mcp := ToolDefinitionToMCP(td)
	if mcp.Name != "my_tool" {
		t.Errorf("name: got %q", mcp.Name)
	}
	if mcp.Description != "Does things" {
		t.Errorf("description: got %q", mcp.Description)
	}

	schemaMap, ok := mcp.InputSchema.(map[string]any)
	if !ok {
		t.Fatalf("inputSchema should be map, got %T", mcp.InputSchema)
	}
	if schemaMap["type"] != "object" {
		t.Errorf("schema type: got %v", schemaMap["type"])
	}
}

func TestToolResponseToMCPSuccess(t *testing.T) {
	result, _ := structpb.NewStruct(map[string]any{
		"text": "operation completed",
	})
	resp := &pluginv1.ToolResponse{
		Success: true,
		Result:  result,
	}

	mcp := ToolResponseToMCP(resp)
	if mcp.IsError {
		t.Error("expected IsError=false")
	}
	if len(mcp.Content) != 1 {
		t.Fatalf("expected 1 content block, got %d", len(mcp.Content))
	}
	if mcp.Content[0].Text != "operation completed" {
		t.Errorf("text: got %q", mcp.Content[0].Text)
	}
}

func TestToolResponseToMCPError(t *testing.T) {
	resp := &pluginv1.ToolResponse{
		Success:      false,
		ErrorCode:    "validation_error",
		ErrorMessage: "title is required",
	}

	mcp := ToolResponseToMCP(resp)
	if !mcp.IsError {
		t.Error("expected IsError=true")
	}
	if mcp.Content[0].Text != "title is required" {
		t.Errorf("text: got %q", mcp.Content[0].Text)
	}
}

func TestToolResponseToMCPFallback(t *testing.T) {
	result, _ := structpb.NewStruct(map[string]any{
		"id":     "abc-123",
		"status": "created",
	})
	resp := &pluginv1.ToolResponse{
		Success: true,
		Result:  result,
	}

	mcp := ToolResponseToMCP(resp)
	if mcp.IsError {
		t.Error("expected IsError=false")
	}

	var m map[string]any
	if err := json.Unmarshal([]byte(mcp.Content[0].Text), &m); err != nil {
		t.Fatalf("fallback text is not valid JSON: %v", err)
	}
	if m["id"] != "abc-123" {
		t.Errorf("fallback id: got %v", m["id"])
	}
}

func TestPromptDefinitionToMCP(t *testing.T) {
	pd := &pluginv1.PromptDefinition{
		Name:        "test-prompt",
		Description: "A test prompt",
		Arguments: []*pluginv1.PromptArgument{
			{Name: "arg1", Description: "First arg", Required: true},
			{Name: "arg2", Description: "Second arg", Required: false},
		},
	}

	mcp := PromptDefinitionToMCP(pd)
	if mcp.Name != "test-prompt" {
		t.Errorf("name: got %q", mcp.Name)
	}
	if len(mcp.Arguments) != 2 {
		t.Fatalf("expected 2 arguments, got %d", len(mcp.Arguments))
	}
	if mcp.Arguments[0].Name != "arg1" || !mcp.Arguments[0].Required {
		t.Errorf("arg1: got %+v", mcp.Arguments[0])
	}
}

func TestPromptGetResponseToMCP(t *testing.T) {
	resp := &pluginv1.PromptGetResponse{
		Description: "Test prompt result",
		Messages: []*pluginv1.PromptMessage{
			{
				Role:    "user",
				Content: &pluginv1.ContentBlock{Type: "text", Text: "Hello world"},
			},
			{
				Role:    "assistant",
				Content: &pluginv1.ContentBlock{Type: "text", Text: "Hi there"},
			},
		},
	}

	mcp := PromptGetResponseToMCP(resp)
	if mcp.Description != "Test prompt result" {
		t.Errorf("description: got %q", mcp.Description)
	}
	if len(mcp.Messages) != 2 {
		t.Fatalf("expected 2 messages, got %d", len(mcp.Messages))
	}
	if mcp.Messages[0].Content.Text != "Hello world" {
		t.Errorf("message 0: got %+v", mcp.Messages[0])
	}
	if mcp.Messages[1].Content.Text != "Hi there" {
		t.Errorf("message 1: got %+v", mcp.Messages[1])
	}
}

// --- ConnState tests ---

func TestConnStateNoAuth(t *testing.T) {
	// When no API key is set, the bridge should not require authentication.
	bridge := NewBridge(&mockSender{}, "")
	state := &connState{authenticated: bridge.apiKey == ""}

	if !state.authenticated {
		t.Error("expected authenticated=true when no API key is set")
	}
}

func TestConnStateRequiresAuth(t *testing.T) {
	bridge := NewBridge(&mockSender{}, "secret")
	state := &connState{authenticated: bridge.apiKey == ""}

	if state.authenticated {
		t.Error("expected authenticated=false when API key is set")
	}
}

// --- Streaming tests ---

// mockStreamSender implements both Sender and StreamSender for testing.
type mockStreamSender struct {
	sendFunc       func(ctx context.Context, req *pluginv1.PluginRequest) (*pluginv1.PluginResponse, error)
	sendStreamFunc func(ctx context.Context, req *pluginv1.PluginRequest) (<-chan *pluginv1.PluginResponse, error)
}

func (m *mockStreamSender) Send(ctx context.Context, req *pluginv1.PluginRequest) (*pluginv1.PluginResponse, error) {
	if m.sendFunc != nil {
		return m.sendFunc(ctx, req)
	}
	return nil, fmt.Errorf("mockStreamSender: no sendFunc configured")
}

func (m *mockStreamSender) SendStream(ctx context.Context, req *pluginv1.PluginRequest) (<-chan *pluginv1.PluginResponse, error) {
	if m.sendStreamFunc != nil {
		return m.sendStreamFunc(ctx, req)
	}
	return nil, fmt.Errorf("mockStreamSender: no sendStreamFunc configured")
}

func TestIsStreamingRequest_True(t *testing.T) {
	bridge := NewBridge(&mockSender{}, "")
	req := &protocol.JSONRPCRequest{
		JSONRPC: "2.0",
		Method:  "tools/call",
		Params:  json.RawMessage(`{"name":"ai_prompt_stream","arguments":{"prompt":"hi"},"streaming":true}`),
	}
	if !bridge.isStreamingRequest(req) {
		t.Error("expected isStreamingRequest=true")
	}
}

func TestIsStreamingRequest_False(t *testing.T) {
	bridge := NewBridge(&mockSender{}, "")
	req := &protocol.JSONRPCRequest{
		JSONRPC: "2.0",
		Method:  "tools/call",
		Params:  json.RawMessage(`{"name":"create_feature","arguments":{}}`),
	}
	if bridge.isStreamingRequest(req) {
		t.Error("expected isStreamingRequest=false when streaming not set")
	}
}

func TestIsStreamingRequest_NilParams(t *testing.T) {
	bridge := NewBridge(&mockSender{}, "")
	req := &protocol.JSONRPCRequest{
		JSONRPC: "2.0",
		Method:  "tools/call",
	}
	if bridge.isStreamingRequest(req) {
		t.Error("expected isStreamingRequest=false for nil params")
	}
}

// TestHandleToolsCallStreaming_FallsBackWhenNoStreamSender verifies that when
// the Sender does not implement StreamSender, the bridge falls back to a
// regular tools/call and returns a normal response.
func TestHandleToolsCallStreaming_FallsBackWhenNoStreamSender(t *testing.T) {
	result, _ := structpb.NewStruct(map[string]any{"text": "ok"})
	sender := &mockSender{
		sendFunc: func(ctx context.Context, req *pluginv1.PluginRequest) (*pluginv1.PluginResponse, error) {
			return &pluginv1.PluginResponse{
				RequestId: req.RequestId,
				Response: &pluginv1.PluginResponse_ToolCall{
					ToolCall: &pluginv1.ToolResponse{Success: true, Result: result},
				},
			}, nil
		},
	}
	resp := dispatchJSON(t, sender, "", `{"jsonrpc":"2.0","id":99,"method":"tools/call","params":{"name":"ai_prompt","arguments":{"prompt":"hi"},"streaming":true}}`)

	if resp.Error != nil {
		t.Fatalf("unexpected error: %+v", resp.Error)
	}
	resultBytes, _ := json.Marshal(resp.Result)
	var mcpResult protocol.MCPToolResult
	if err := json.Unmarshal(resultBytes, &mcpResult); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if mcpResult.IsError {
		t.Error("expected isError=false")
	}
}

// TestHandleToolsCallStreaming_StreamsChunks verifies that when the Sender
// implements StreamSender, chunks are written as notifications and a final
// response is returned.
func TestHandleToolsCallStreaming_StreamsChunks(t *testing.T) {
	sender := &mockStreamSender{
		sendStreamFunc: func(ctx context.Context, req *pluginv1.PluginRequest) (<-chan *pluginv1.PluginResponse, error) {
			ss := req.GetStreamStart()
			if ss == nil {
				t.Error("expected StreamStart request")
			}
			ch := make(chan *pluginv1.PluginResponse, 4)
			ch <- &pluginv1.PluginResponse{
				Response: &pluginv1.PluginResponse_StreamChunk{
					StreamChunk: &pluginv1.StreamChunk{StreamId: ss.StreamId, Data: []byte("Hello "), Sequence: 0},
				},
			}
			ch <- &pluginv1.PluginResponse{
				Response: &pluginv1.PluginResponse_StreamChunk{
					StreamChunk: &pluginv1.StreamChunk{StreamId: ss.StreamId, Data: []byte("world"), Sequence: 1},
				},
			}
			ch <- &pluginv1.PluginResponse{
				Response: &pluginv1.PluginResponse_StreamEnd{
					StreamEnd: &pluginv1.StreamEnd{StreamId: ss.StreamId, Success: true, TotalChunks: 2},
				},
			}
			close(ch)
			return ch, nil
		},
	}

	bridge := NewBridge(sender, "")

	// Write the request into a buffer, run handleToolsCallStreaming, read back
	// the framed responses (notifications + final response).
	req := &protocol.JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      float64(7),
		Method:  "tools/call",
		Params:  json.RawMessage(`{"name":"ai_prompt_stream","arguments":{"prompt":"hi"},"streaming":true}`),
	}

	// Use a pipe to simulate a QUIC stream.
	var buf bytes.Buffer
	bridge.handleToolsCallStreaming(context.Background(), &buf, req)

	// Read all framed messages from the buffer.
	var messages []json.RawMessage
	for buf.Len() > 0 {
		var msg json.RawMessage
		if err := readJSONFrame(&buf, &msg); err != nil {
			break
		}
		messages = append(messages, msg)
	}

	// Expect 2 notifications + 1 final response = 3 messages.
	if len(messages) != 3 {
		t.Fatalf("expected 3 messages (2 chunks + 1 response), got %d", len(messages))
	}

	// First two should be notifications.
	for i, raw := range messages[:2] {
		var notif map[string]any
		if err := json.Unmarshal(raw, &notif); err != nil {
			t.Fatalf("message %d: unmarshal: %v", i, err)
		}
		if notif["method"] != "notifications/stream" {
			t.Errorf("message %d: expected method=notifications/stream, got %v", i, notif["method"])
		}
		params, _ := notif["params"].(map[string]any)
		if params["data"] == "" {
			t.Errorf("message %d: expected non-empty data", i)
		}
	}

	// Last should be the final response with id=7.
	var finalResp protocol.JSONRPCResponse
	if err := json.Unmarshal(messages[2], &finalResp); err != nil {
		t.Fatalf("unmarshal final response: %v", err)
	}
	if finalResp.Error != nil {
		t.Errorf("expected no error in final response, got: %+v", finalResp.Error)
	}
	if finalResp.ID != float64(7) {
		t.Errorf("final response ID: got %v, want 7", finalResp.ID)
	}
}

// TestHandleToolsCallStreaming_StreamError verifies that a StreamEnd with
// success=false results in a JSON-RPC error response.
func TestHandleToolsCallStreaming_StreamError(t *testing.T) {
	sender := &mockStreamSender{
		sendStreamFunc: func(ctx context.Context, req *pluginv1.PluginRequest) (<-chan *pluginv1.PluginResponse, error) {
			ss := req.GetStreamStart()
			ch := make(chan *pluginv1.PluginResponse, 1)
			ch <- &pluginv1.PluginResponse{
				Response: &pluginv1.PluginResponse_StreamEnd{
					StreamEnd: &pluginv1.StreamEnd{
						StreamId:     ss.StreamId,
						Success:      false,
						ErrorCode:    "handler_error",
						ErrorMessage: "something went wrong",
					},
				},
			}
			close(ch)
			return ch, nil
		},
	}

	bridge := NewBridge(sender, "")
	req := &protocol.JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      float64(8),
		Method:  "tools/call",
		Params:  json.RawMessage(`{"name":"ai_prompt_stream","arguments":{"prompt":"fail"},"streaming":true}`),
	}

	var buf bytes.Buffer
	bridge.handleToolsCallStreaming(context.Background(), &buf, req)

	var finalResp protocol.JSONRPCResponse
	if err := readJSONFrame(&buf, &finalResp); err != nil {
		t.Fatalf("read final response: %v", err)
	}
	if finalResp.Error == nil {
		t.Fatal("expected error response for stream failure")
	}
	if !strings.Contains(finalResp.Error.Message, "something went wrong") {
		t.Errorf("error message: got %q", finalResp.Error.Message)
	}
}

