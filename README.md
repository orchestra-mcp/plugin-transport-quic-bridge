# Orchestra Plugin: transport-quic-bridge

A transport plugin for the [Orchestra MCP](https://github.com/orchestra-mcp/framework) framework that bridges remote native clients (desktop/mobile apps) to the orchestrator over **QUIC + mTLS**.

For browser clients, use `orchestra serve --web-gate :9201` instead — it provides a WebSocket JSON-RPC gateway directly from the in-process router.

## Install

```bash
go install github.com/orchestra-mcp/plugin-transport-quic-bridge/cmd@latest
```

## Usage

```bash
transport-quic-bridge \
  --orchestrator-addr localhost:9100 \
  --listen-addr :9200 \
  --certs-dir ~/.orchestra/certs \
  --api-key my-secret-key
```

### Environment Variables

All flags can be configured via environment variables:

| Flag | Env Var | Default | Description |
|------|---------|---------|-------------|
| `--orchestrator-addr` | `ORCHESTRA_ORCHESTRATOR_ADDR` | `localhost:9100` | Orchestrator QUIC address |
| `--listen-addr` | `ORCHESTRA_LISTEN_ADDR` | `:9200` | QUIC listener address |
| `--certs-dir` | `ORCHESTRA_CERTS_DIR` | `~/.orchestra/certs` | mTLS certificate directory |
| `--api-key` | `ORCHESTRA_API_KEY` | *(no auth)* | API key for client auth |

## How It Works

This transport plugin connects to the Orchestra orchestrator via mTLS QUIC and exposes a QUIC endpoint for native desktop/mobile apps. Each request-response pair uses a dedicated QUIC bidirectional stream with length-delimited JSON-RPC 2.0 framing.

### Protocol

- **Framing:** `[4-byte big-endian uint32 length][JSON payload]`
- **Max message size:** 16 MB
- **TLS:** 1.3 (server-only, not mTLS for clients)
- **ALPN:** `orchestra-bridge`

### Supported Methods

| Method | Description |
|--------|-------------|
| `initialize` | MCP protocol handshake |
| `ping` | Health check (returns `{}`) |
| `tools/list` | List all available MCP tools |
| `tools/call` | Call an MCP tool |
| `prompts/list` | List available prompts |
| `prompts/get` | Get a prompt by name |
| `authenticate` | Authenticate with API key |

### Authentication

First stream must send `authenticate` method with matching API key. All subsequent streams on the same connection are pre-authenticated. If API key is not configured, all connections are allowed.

## Related Packages

- [sdk-go](https://github.com/orchestra-mcp/sdk-go) — Plugin SDK
- [gen-go](https://github.com/orchestra-mcp/gen-go) — Generated Protobuf types
