package internal

import (
	"encoding/json"
	"fmt"

	pluginv1 "github.com/orchestra-mcp/gen-go/orchestra/plugin/v1"
	"github.com/orchestra-mcp/sdk-go/protocol"
	"google.golang.org/protobuf/types/known/structpb"
)

// ToolDefinitionToMCP converts a protobuf ToolDefinition to an MCP-compatible
// MCPToolDefinition. The InputSchema (a protobuf Struct) is converted to a
// native Go map so it serializes as a JSON object.
func ToolDefinitionToMCP(td *pluginv1.ToolDefinition) protocol.MCPToolDefinition {
	var inputSchema any
	if td.GetInputSchema() != nil {
		inputSchema = StructToMap(td.GetInputSchema())
	}

	return protocol.MCPToolDefinition{
		Name:        td.GetName(),
		Description: td.GetDescription(),
		InputSchema: inputSchema,
	}
}

// ToolResponseToMCP converts a protobuf ToolResponse to an MCP MCPToolResult.
// Successful responses extract the "text" field from the result Struct.
// Failed responses produce an error content block with the error message.
func ToolResponseToMCP(resp *pluginv1.ToolResponse) protocol.MCPToolResult {
	if !resp.GetSuccess() {
		errMsg := resp.GetErrorMessage()
		if errMsg == "" {
			errMsg = fmt.Sprintf("tool error: %s", resp.GetErrorCode())
		}
		return protocol.MCPToolResult{
			Content: []protocol.MCPContent{
				{Type: "text", Text: errMsg},
			},
			IsError: true,
		}
	}

	// Extract text from the result struct. Tools typically return
	// {"text": "..."} in the Result field.
	text := extractResultText(resp.GetResult())

	return protocol.MCPToolResult{
		Content: []protocol.MCPContent{
			{Type: "text", Text: text},
		},
	}
}

// extractResultText attempts to get a human-readable string from a tool result
// Struct. It first looks for a "text" field. If not found, it falls back to
// JSON-serializing the entire struct.
func extractResultText(s *structpb.Struct) string {
	if s == nil {
		return ""
	}

	// Check for a "text" field.
	if v, ok := s.GetFields()["text"]; ok {
		return v.GetStringValue()
	}

	// Fall back to JSON serialization of the whole result.
	m := StructToMap(s)
	data, err := json.Marshal(m)
	if err != nil {
		return fmt.Sprintf("%v", m)
	}
	return string(data)
}

// StructToMap converts a protobuf Struct to a native Go map[string]any.
// This allows the value to serialize as a proper JSON object rather than the
// protobuf JSON representation.
func StructToMap(s *structpb.Struct) map[string]any {
	if s == nil {
		return nil
	}
	result := make(map[string]any, len(s.GetFields()))
	for k, v := range s.GetFields() {
		result[k] = valueToInterface(v)
	}
	return result
}

// MapToStruct converts a native Go map to a protobuf Struct. Returns an error
// if the map contains types that cannot be represented in protobuf.
func MapToStruct(m map[string]any) (*structpb.Struct, error) {
	return structpb.NewStruct(m)
}

// PromptDefinitionToMCP converts a protobuf PromptDefinition to an
// MCP-compatible MCPPromptDefinition.
func PromptDefinitionToMCP(pd *pluginv1.PromptDefinition) protocol.MCPPromptDefinition {
	args := make([]protocol.MCPPromptArgument, 0, len(pd.GetArguments()))
	for _, a := range pd.GetArguments() {
		args = append(args, protocol.MCPPromptArgument{
			Name:        a.GetName(),
			Description: a.GetDescription(),
			Required:    a.GetRequired(),
		})
	}
	return protocol.MCPPromptDefinition{
		Name:        pd.GetName(),
		Description: pd.GetDescription(),
		Arguments:   args,
	}
}

// PromptGetResponseToMCP converts a protobuf PromptGetResponse to an MCP
// MCPPromptResult.
func PromptGetResponseToMCP(resp *pluginv1.PromptGetResponse) protocol.MCPPromptResult {
	msgs := make([]protocol.MCPPromptMessage, 0, len(resp.GetMessages()))
	for _, m := range resp.GetMessages() {
		msg := protocol.MCPPromptMessage{
			Role: m.GetRole(),
		}
		if c := m.GetContent(); c != nil {
			msg.Content = protocol.MCPContent{
				Type: c.GetType(),
				Text: c.GetText(),
			}
		}
		msgs = append(msgs, msg)
	}
	return protocol.MCPPromptResult{
		Description: resp.GetDescription(),
		Messages:    msgs,
	}
}

// valueToInterface converts a protobuf Value to a native Go interface.
func valueToInterface(v *structpb.Value) any {
	if v == nil {
		return nil
	}
	switch k := v.GetKind().(type) {
	case *structpb.Value_NullValue:
		return nil
	case *structpb.Value_NumberValue:
		return k.NumberValue
	case *structpb.Value_StringValue:
		return k.StringValue
	case *structpb.Value_BoolValue:
		return k.BoolValue
	case *structpb.Value_StructValue:
		return StructToMap(k.StructValue)
	case *structpb.Value_ListValue:
		if k.ListValue == nil {
			return nil
		}
		items := make([]any, len(k.ListValue.GetValues()))
		for i, item := range k.ListValue.GetValues() {
			items[i] = valueToInterface(item)
		}
		return items
	default:
		return nil
	}
}
