# Protocol

## Overview

The QUIC bridge plugin exposes a QUIC transport for remote native clients (desktop/mobile apps). It forwards length-delimited JSON-RPC 2.0 requests to the Orchestra orchestrator via mTLS QUIC, translating between JSON-RPC 2.0 and Protobuf.

For browser clients, use `orchestra serve --web-gate` instead — it provides a WebSocket JSON-RPC gateway.

## Message Flow

```
Native App                     Bridge                    Orchestrator
    |                            |                            |
    |-- JSON-RPC request ------->|                            |
    |   (QUIC stream)            |-- Protobuf request ------->|
    |                            |                            |
    |                            |<-- Protobuf response ------|
    |<-- JSON-RPC response ------|                            |
    |                            |                            |
```

## QUIC Transport (port 9200)

- Each request-response pair uses a dedicated QUIC bidirectional stream
- Messages use **length-delimited framing**: `[4-byte big-endian uint32 length][JSON payload]`
- Max message size: 16 MB
- TLS 1.3 (server-only, not mTLS — clients don't need Orchestra CA certs)
- ALPN: `orchestra-bridge`

## Supported Methods

| Method | Description | Request Params | Response |
|--------|-------------|---------------|----------|
| `initialize` | MCP protocol handshake | `{}` | `{protocolVersion, capabilities, serverInfo}` |
| `ping` | Health check | — | `{}` |
| `authenticate` | API key auth | `{api_key: string}` | `{authenticated: true}` |
| `tools/list` | List all MCP tools | — | `{tools: ToolDefinition[]}` |
| `tools/call` | Invoke an MCP tool | `{name, arguments, streaming?}` | `{content, isError}` |
| `prompts/list` | List all prompts | — | `{prompts: PromptDefinition[]}` |
| `prompts/get` | Get a prompt | `{name, arguments?}` | `{description, messages}` |
| `notifications/*` | Client notifications | — | *(no response)* |

## Authentication

Authentication is optional (controlled by `--api-key` flag).

- First stream must send `authenticate` method with matching API key
- All subsequent streams on the same connection are pre-authenticated
- If API key is not configured, all connections are allowed without auth

## Streaming

For tools that support streaming (e.g., AI responses), set `"streaming": true` in `tools/call` params.

**Flow:**
1. Client sends: `{"method":"tools/call","params":{"name":"...","streaming":true}}`
2. Bridge sends stream chunks as JSON-RPC notifications: `{"method":"notifications/stream","params":{"stream_id","sequence","data"}}`
3. Bridge sends final response: `{"id":N,"result":{"content":[{"text":"[streamed N chunks]"}]}}`

## Request ID Prefixes

The bridge prefixes request IDs for traceability:

| Method | Prefix |
|--------|--------|
| tools/list | `quic-lt-` |
| tools/call | `quic-tc-` |
| prompts/list | `quic-lp-` |
| prompts/get | `quic-pg-` |
| streaming | `quic-st-` |

## Error Codes

Standard JSON-RPC 2.0 error codes:

| Code | Constant | Meaning |
|------|----------|---------|
| -32700 | ParseError | Malformed JSON |
| -32600 | InvalidRequest | Auth required or failed |
| -32602 | InvalidParams | Missing/invalid parameters |
| -32603 | InternalError | Orchestrator unreachable or unexpected response |
| -32601 | MethodNotFound | Unknown method |
