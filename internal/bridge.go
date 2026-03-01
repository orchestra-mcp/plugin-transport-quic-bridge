// Package internal implements the QUIC bridge that accepts remote client
// connections and forwards JSON-RPC 2.0 requests to the Orchestra orchestrator.
// Each client request arrives on its own bidirectional QUIC stream using
// length-delimited JSON framing.
package internal

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"sync"
	"time"

	pluginv1 "github.com/orchestra-mcp/gen-go/orchestra/plugin/v1"
	"github.com/orchestra-mcp/sdk-go/protocol"
	"github.com/quic-go/quic-go"
	"google.golang.org/protobuf/types/known/structpb"
)

// Sender abstracts the QUIC client so the Bridge can be tested without a real
// network connection. In production this is backed by plugin.OrchestratorClient.
type Sender interface {
	Send(ctx context.Context, req *pluginv1.PluginRequest) (*pluginv1.PluginResponse, error)
}

// StreamSender is an optional extension of Sender for tools that stream
// multiple responses. If the Sender also implements StreamSender, streaming
// tool calls (tools/call with streaming=true) will use SendStream instead of
// Send, forwarding each StreamChunk as a JSON-RPC notification to the client.
type StreamSender interface {
	SendStream(ctx context.Context, req *pluginv1.PluginRequest) (<-chan *pluginv1.PluginResponse, error)
}

// Bridge accepts QUIC connections from remote clients and forwards their
// JSON-RPC 2.0 requests to the orchestrator.
type Bridge struct {
	sender   Sender
	apiKey   string // optional API key (empty = no auth required)
	listener *quic.Listener
}

// NewBridge creates a new Bridge that forwards requests through the given
// sender. If apiKey is empty, authentication is disabled.
func NewBridge(sender Sender, apiKey string) *Bridge {
	return &Bridge{
		sender: sender,
		apiKey: apiKey,
	}
}

// ListenAndServe starts the QUIC listener for remote clients. It uses regular
// TLS (not mTLS) since remote clients do not have Orchestra CA certificates.
// The method blocks until the context is cancelled or an unrecoverable error
// occurs.
func (b *Bridge) ListenAndServe(ctx context.Context, addr string, tlsConfig *tls.Config) error {
	listener, err := quic.ListenAddr(addr, tlsConfig, &quic.Config{
		MaxIdleTimeout:  5 * time.Minute,
		KeepAlivePeriod: 15 * time.Second,
	})
	if err != nil {
		return fmt.Errorf("quic listen %s: %w", addr, err)
	}
	b.listener = listener
	defer listener.Close()

	// Close the listener when the context is cancelled.
	go func() {
		<-ctx.Done()
		listener.Close()
	}()

	for {
		conn, err := listener.Accept(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return nil // graceful shutdown
			}
			return fmt.Errorf("accept connection: %w", err)
		}
		go b.handleConnection(ctx, conn)
	}
}

// connState tracks per-connection authentication state. Access is protected by
// a mutex since multiple streams on the same connection run concurrently.
type connState struct {
	mu            sync.Mutex
	authenticated bool
}

// handleConnection manages a single remote client connection. It tracks
// authentication state and accepts streams in a loop.
func (b *Bridge) handleConnection(ctx context.Context, conn quic.Connection) {
	defer conn.CloseWithError(0, "")

	state := &connState{
		authenticated: b.apiKey == "", // no auth required if no API key is set
	}

	for {
		stream, err := conn.AcceptStream(ctx)
		if err != nil {
			return // connection closed
		}
		go b.handleStream(ctx, stream, state)
	}
}

// handleStream processes a single request on a QUIC stream. Each stream carries
// one JSON-RPC request-response pair using length-delimited framing.
func (b *Bridge) handleStream(ctx context.Context, stream quic.Stream, state *connState) {
	defer stream.Close()

	// Read the length-delimited JSON request.
	var req protocol.JSONRPCRequest
	if err := readJSONFrame(stream, &req); err != nil {
		log.Printf("quic-bridge: read request: %v", err)
		// Try to write a parse error response.
		errResp := &protocol.JSONRPCResponse{
			JSONRPC: "2.0",
			Error: &protocol.JSONRPCError{
				Code:    protocol.ParseError,
				Message: fmt.Sprintf("failed to read request: %v", err),
			},
		}
		_ = writeJSONFrame(stream, errResp)
		return
	}

	// Check authentication.
	state.mu.Lock()
	isAuthenticated := state.authenticated
	state.mu.Unlock()

	if !isAuthenticated {
		// Only allow the "authenticate" method until authenticated.
		if req.Method != "authenticate" {
			resp := &protocol.JSONRPCResponse{
				JSONRPC: "2.0",
				ID:      req.ID,
				Error: &protocol.JSONRPCError{
					Code:    protocol.InvalidRequest,
					Message: "authentication required: send 'authenticate' method first",
				},
			}
			if err := writeJSONFrame(stream, resp); err != nil {
				log.Printf("quic-bridge: write auth error: %v", err)
			}
			return
		}

		// Handle authentication.
		resp := b.handleAuthenticate(&req)
		if resp.Error == nil {
			state.mu.Lock()
			state.authenticated = true
			state.mu.Unlock()
		}
		if err := writeJSONFrame(stream, resp); err != nil {
			log.Printf("quic-bridge: write auth response: %v", err)
		}
		return
	}

	// For streaming tool calls, keep the stream open and forward chunks.
	if req.Method == "tools/call" && b.isStreamingRequest(&req) {
		b.handleToolsCallStreaming(ctx, stream, &req)
		return
	}

	// Dispatch the authenticated request.
	resp := b.dispatch(ctx, &req)

	// Notifications (no ID) get no response.
	if resp == nil {
		return
	}

	if err := writeJSONFrame(stream, resp); err != nil {
		log.Printf("quic-bridge: write response: %v", err)
	}
}

// isStreamingRequest returns true when a tools/call request has "streaming":true
// in its params, signalling that the caller wants chunk-by-chunk output.
func (b *Bridge) isStreamingRequest(req *protocol.JSONRPCRequest) bool {
	if req.Params == nil {
		return false
	}
	var p map[string]any
	if err := json.Unmarshal(req.Params, &p); err != nil {
		return false
	}
	v, _ := p["streaming"].(bool)
	return v
}

// streamNotification is a JSON-RPC notification (no id) used to push stream
// chunks to the remote client without waiting for a response.
type streamNotification struct {
	JSONRPC string `json:"jsonrpc"`
	Method  string `json:"method"`
	Params  any    `json:"params"`
}

// handleToolsCallStreaming forwards a streaming tool call to the orchestrator
// via SendStream. Each StreamChunk is written as a notifications/stream frame
// to w before the final response closes the exchange. w is an io.Writer so
// this function can be tested without a real QUIC stream.
func (b *Bridge) handleToolsCallStreaming(ctx context.Context, w io.Writer, req *protocol.JSONRPCRequest) {
	ss, ok := b.sender.(StreamSender)
	if !ok {
		// Sender does not support streaming — fall back to regular call.
		resp := b.handleToolsCall(ctx, req)
		if resp != nil {
			_ = writeJSONFrame(w, resp)
		}
		return
	}

	var params toolCallParams
	if req.Params != nil {
		_ = json.Unmarshal(req.Params, &params)
	}
	if params.Name == "" {
		_ = writeJSONFrame(w, &protocol.JSONRPCResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Error: &protocol.JSONRPCError{
				Code:    protocol.InvalidParams,
				Message: "missing required parameter: name",
			},
		})
		return
	}

	var args *structpb.Struct
	if params.Arguments != nil {
		var err error
		args, err = structpb.NewStruct(params.Arguments)
		if err != nil {
			_ = writeJSONFrame(w, &protocol.JSONRPCResponse{
				JSONRPC: "2.0",
				ID:      req.ID,
				Error: &protocol.JSONRPCError{
					Code:    protocol.InvalidParams,
					Message: fmt.Sprintf("invalid arguments: %v", err),
				},
			})
			return
		}
	}

	streamID := fmt.Sprintf("quic-stream-%v", req.ID)

	ch, err := ss.SendStream(ctx, &pluginv1.PluginRequest{
		RequestId: fmt.Sprintf("quic-st-%v", req.ID),
		Request: &pluginv1.PluginRequest_StreamStart{
			StreamStart: &pluginv1.StreamStart{
				StreamId:     streamID,
				ToolName:     params.Name,
				Arguments:    args,
				CallerPlugin: "transport.quic-bridge",
			},
		},
	})
	if err != nil {
		_ = writeJSONFrame(w, &protocol.JSONRPCResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Error: &protocol.JSONRPCError{
				Code:    protocol.InternalError,
				Message: fmt.Sprintf("orchestrator stream failed: %v", err),
			},
		})
		return
	}

	// Forward each StreamChunk as a notifications/stream notification,
	// then send the final response when StreamEnd arrives.
	var totalChunks int64
	var streamErr string
	for resp := range ch {
		if chunk := resp.GetStreamChunk(); chunk != nil {
			totalChunks++
			notif := &streamNotification{
				JSONRPC: "2.0",
				Method:  "notifications/stream",
				Params: map[string]any{
					"stream_id": chunk.StreamId,
					"sequence":  chunk.Sequence,
					"data":      string(chunk.Data),
				},
			}
			if err := writeJSONFrame(w, notif); err != nil {
				log.Printf("quic-bridge: write stream notification: %v", err)
				return
			}
		}
		if end := resp.GetStreamEnd(); end != nil {
			if !end.Success {
				streamErr = end.ErrorMessage
			}
			break
		}
	}

	// Send the final JSON-RPC response.
	if streamErr != "" {
		_ = writeJSONFrame(w, &protocol.JSONRPCResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Error: &protocol.JSONRPCError{
				Code:    protocol.InternalError,
				Message: streamErr,
			},
		})
		return
	}

	_ = writeJSONFrame(w, &protocol.JSONRPCResponse{
		JSONRPC: "2.0",
		ID:      req.ID,
		Result: map[string]any{
			"content": []any{
				map[string]any{"type": "text", "text": fmt.Sprintf("[streamed %d chunks]", totalChunks)},
			},
			"isError": false,
		},
	})
}

// dispatch routes a JSON-RPC request to the orchestrator via the appropriate
// protobuf request type.
func (b *Bridge) dispatch(ctx context.Context, req *protocol.JSONRPCRequest) *protocol.JSONRPCResponse {
	switch req.Method {
	case "initialize":
		return b.handleInitialize(req)
	case "ping":
		return b.handlePing(req)
	case "tools/list":
		return b.handleToolsList(ctx, req)
	case "tools/call":
		return b.handleToolsCall(ctx, req)
	case "prompts/list":
		return b.handlePromptsList(ctx, req)
	case "prompts/get":
		return b.handlePromptsGet(ctx, req)
	default:
		// Notifications get no response.
		if len(req.Method) > 14 && req.Method[:14] == "notifications/" {
			log.Printf("quic-bridge: notification: %s", req.Method)
			return nil
		}
		return &protocol.JSONRPCResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Error: &protocol.JSONRPCError{
				Code:    protocol.MethodNotFound,
				Message: fmt.Sprintf("method not found: %s", req.Method),
			},
		}
	}
}

// handleInitialize responds to the MCP initialize handshake. No orchestrator
// communication is needed.
func (b *Bridge) handleInitialize(req *protocol.JSONRPCRequest) *protocol.JSONRPCResponse {
	return &protocol.JSONRPCResponse{
		JSONRPC: "2.0",
		ID:      req.ID,
		Result: protocol.MCPInitializeResult{
			ProtocolVersion: "2024-11-05",
			Capabilities: protocol.MCPServerCapabilities{
				Tools:   &protocol.MCPToolsCapability{},
				Prompts: &protocol.MCPPromptsCapability{},
			},
			ServerInfo: protocol.MCPServerInfo{
				Name:    "orchestra",
				Version: "1.0.0",
			},
		},
	}
}

// handlePing responds with an empty result object (pong).
func (b *Bridge) handlePing(req *protocol.JSONRPCRequest) *protocol.JSONRPCResponse {
	return &protocol.JSONRPCResponse{
		JSONRPC: "2.0",
		ID:      req.ID,
		Result:  map[string]any{},
	}
}

// toolsListResult is the JSON shape for a tools/list response.
type toolsListResult struct {
	Tools []protocol.MCPToolDefinition `json:"tools"`
}

// handleToolsList queries the orchestrator for all registered tools.
func (b *Bridge) handleToolsList(ctx context.Context, req *protocol.JSONRPCRequest) *protocol.JSONRPCResponse {
	resp, err := b.sender.Send(ctx, &pluginv1.PluginRequest{
		RequestId: fmt.Sprintf("quic-lt-%v", req.ID),
		Request: &pluginv1.PluginRequest_ListTools{
			ListTools: &pluginv1.ListToolsRequest{},
		},
	})
	if err != nil {
		return &protocol.JSONRPCResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Error: &protocol.JSONRPCError{
				Code:    protocol.InternalError,
				Message: fmt.Sprintf("orchestrator list_tools failed: %v", err),
			},
		}
	}

	lt := resp.GetListTools()
	if lt == nil {
		return &protocol.JSONRPCResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Error: &protocol.JSONRPCError{
				Code:    protocol.InternalError,
				Message: "unexpected response type from orchestrator",
			},
		}
	}

	mcpTools := make([]protocol.MCPToolDefinition, 0, len(lt.Tools))
	for _, td := range lt.Tools {
		mcpTools = append(mcpTools, ToolDefinitionToMCP(td))
	}

	return &protocol.JSONRPCResponse{
		JSONRPC: "2.0",
		ID:      req.ID,
		Result:  toolsListResult{Tools: mcpTools},
	}
}

// toolCallParams is the expected shape of params for a tools/call request.
type toolCallParams struct {
	Name      string         `json:"name"`
	Arguments map[string]any `json:"arguments,omitempty"`
}

// handleToolsCall sends a tool invocation to the orchestrator.
func (b *Bridge) handleToolsCall(ctx context.Context, req *protocol.JSONRPCRequest) *protocol.JSONRPCResponse {
	var params toolCallParams
	if req.Params != nil {
		if err := json.Unmarshal(req.Params, &params); err != nil {
			return &protocol.JSONRPCResponse{
				JSONRPC: "2.0",
				ID:      req.ID,
				Error: &protocol.JSONRPCError{
					Code:    protocol.InvalidParams,
					Message: fmt.Sprintf("invalid params: %v", err),
				},
			}
		}
	}

	if params.Name == "" {
		return &protocol.JSONRPCResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Error: &protocol.JSONRPCError{
				Code:    protocol.InvalidParams,
				Message: "missing required parameter: name",
			},
		}
	}

	// Convert arguments map to protobuf Struct.
	var args *structpb.Struct
	if params.Arguments != nil {
		var err error
		args, err = structpb.NewStruct(params.Arguments)
		if err != nil {
			return &protocol.JSONRPCResponse{
				JSONRPC: "2.0",
				ID:      req.ID,
				Error: &protocol.JSONRPCError{
					Code:    protocol.InvalidParams,
					Message: fmt.Sprintf("invalid arguments: %v", err),
				},
			}
		}
	}

	resp, err := b.sender.Send(ctx, &pluginv1.PluginRequest{
		RequestId: fmt.Sprintf("quic-tc-%v", req.ID),
		Request: &pluginv1.PluginRequest_ToolCall{
			ToolCall: &pluginv1.ToolRequest{
				ToolName:     params.Name,
				Arguments:    args,
				CallerPlugin: "transport.quic-bridge",
			},
		},
	})
	if err != nil {
		return &protocol.JSONRPCResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Error: &protocol.JSONRPCError{
				Code:    protocol.InternalError,
				Message: fmt.Sprintf("orchestrator tool_call failed: %v", err),
			},
		}
	}

	tc := resp.GetToolCall()
	if tc == nil {
		return &protocol.JSONRPCResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Error: &protocol.JSONRPCError{
				Code:    protocol.InternalError,
				Message: "unexpected response type from orchestrator",
			},
		}
	}

	mcpResult := ToolResponseToMCP(tc)

	return &protocol.JSONRPCResponse{
		JSONRPC: "2.0",
		ID:      req.ID,
		Result:  mcpResult,
	}
}

// promptsListResult is the JSON shape for a prompts/list response.
type promptsListResult struct {
	Prompts []protocol.MCPPromptDefinition `json:"prompts"`
}

// handlePromptsList queries the orchestrator for all registered prompts.
func (b *Bridge) handlePromptsList(ctx context.Context, req *protocol.JSONRPCRequest) *protocol.JSONRPCResponse {
	resp, err := b.sender.Send(ctx, &pluginv1.PluginRequest{
		RequestId: fmt.Sprintf("quic-lp-%v", req.ID),
		Request: &pluginv1.PluginRequest_ListPrompts{
			ListPrompts: &pluginv1.ListPromptsRequest{},
		},
	})
	if err != nil {
		return &protocol.JSONRPCResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Error: &protocol.JSONRPCError{
				Code:    protocol.InternalError,
				Message: fmt.Sprintf("orchestrator list_prompts failed: %v", err),
			},
		}
	}

	lp := resp.GetListPrompts()
	if lp == nil {
		return &protocol.JSONRPCResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Error: &protocol.JSONRPCError{
				Code:    protocol.InternalError,
				Message: "unexpected response type from orchestrator",
			},
		}
	}

	mcpPrompts := make([]protocol.MCPPromptDefinition, 0, len(lp.Prompts))
	for _, pd := range lp.Prompts {
		mcpPrompts = append(mcpPrompts, PromptDefinitionToMCP(pd))
	}

	return &protocol.JSONRPCResponse{
		JSONRPC: "2.0",
		ID:      req.ID,
		Result:  promptsListResult{Prompts: mcpPrompts},
	}
}

// promptGetParams is the expected shape of params for a prompts/get request.
type promptGetParams struct {
	Name      string            `json:"name"`
	Arguments map[string]string `json:"arguments,omitempty"`
}

// handlePromptsGet sends a prompt get request to the orchestrator.
func (b *Bridge) handlePromptsGet(ctx context.Context, req *protocol.JSONRPCRequest) *protocol.JSONRPCResponse {
	var params promptGetParams
	if req.Params != nil {
		if err := json.Unmarshal(req.Params, &params); err != nil {
			return &protocol.JSONRPCResponse{
				JSONRPC: "2.0",
				ID:      req.ID,
				Error: &protocol.JSONRPCError{
					Code:    protocol.InvalidParams,
					Message: fmt.Sprintf("invalid params: %v", err),
				},
			}
		}
	}

	if params.Name == "" {
		return &protocol.JSONRPCResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Error: &protocol.JSONRPCError{
				Code:    protocol.InvalidParams,
				Message: "missing required parameter: name",
			},
		}
	}

	resp, err := b.sender.Send(ctx, &pluginv1.PluginRequest{
		RequestId: fmt.Sprintf("quic-pg-%v", req.ID),
		Request: &pluginv1.PluginRequest_PromptGet{
			PromptGet: &pluginv1.PromptGetRequest{
				PromptName: params.Name,
				Arguments:  params.Arguments,
			},
		},
	})
	if err != nil {
		return &protocol.JSONRPCResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Error: &protocol.JSONRPCError{
				Code:    protocol.InternalError,
				Message: fmt.Sprintf("orchestrator prompt_get failed: %v", err),
			},
		}
	}

	pg := resp.GetPromptGet()
	if pg == nil {
		return &protocol.JSONRPCResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Error: &protocol.JSONRPCError{
				Code:    protocol.InternalError,
				Message: "unexpected response type from orchestrator",
			},
		}
	}

	mcpResult := PromptGetResponseToMCP(pg)

	return &protocol.JSONRPCResponse{
		JSONRPC: "2.0",
		ID:      req.ID,
		Result:  mcpResult,
	}
}
