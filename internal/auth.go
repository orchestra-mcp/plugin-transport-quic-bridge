package internal

import (
	"encoding/json"

	"github.com/orchestra-mcp/sdk-go/protocol"
)

// authenticateParams is the expected shape of the "authenticate" method params.
type authenticateParams struct {
	APIKey string `json:"api_key"`
}

// handleAuthenticate validates the client's API key. Returns a success response
// if the key matches, or an error response if it does not.
func (b *Bridge) handleAuthenticate(req *protocol.JSONRPCRequest) *protocol.JSONRPCResponse {
	var params authenticateParams
	if req.Params != nil {
		if err := json.Unmarshal(req.Params, &params); err != nil {
			return &protocol.JSONRPCResponse{
				JSONRPC: "2.0",
				ID:      req.ID,
				Error: &protocol.JSONRPCError{
					Code:    protocol.InvalidParams,
					Message: "invalid authenticate params: expected {\"api_key\": \"...\"}",
				},
			}
		}
	}

	if params.APIKey == "" {
		return &protocol.JSONRPCResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Error: &protocol.JSONRPCError{
				Code:    protocol.InvalidParams,
				Message: "missing required parameter: api_key",
			},
		}
	}

	if params.APIKey != b.apiKey {
		return &protocol.JSONRPCResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Error: &protocol.JSONRPCError{
				Code:    protocol.InvalidRequest,
				Message: "authentication failed: invalid API key",
			},
		}
	}

	return &protocol.JSONRPCResponse{
		JSONRPC: "2.0",
		ID:      req.ID,
		Result: map[string]any{
			"authenticated": true,
		},
	}
}
