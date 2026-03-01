# Orchestra Plugin: transport-quic-bridge

A transport plugin for the [Orchestra MCP](https://github.com/orchestra-mcp/framework) framework.

## Install

```bash
go install github.com/orchestra-mcp/plugin-transport-quic-bridge/cmd@latest
```

## Usage

```bash
transport-quic-bridge --orchestrator-addr localhost:9100 --certs-dir ~/.orchestra/certs
```

## How It Works

This transport plugin connects to the Orchestra orchestrator as a client and
bridges an external protocol to the internal QUIC mesh.

## Related Packages

- [sdk-go](https://github.com/orchestra-mcp/sdk-go) — Plugin SDK
- [gen-go](https://github.com/orchestra-mcp/gen-go) — Generated Protobuf types
