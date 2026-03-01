# Protocol

## Overview

This transport plugin bridges an external protocol to the Orchestra orchestrator.

## Supported Methods

| Method | Description |
|--------|-------------|
| `initialize` | Protocol handshake |
| `ping` | Health check |

## Message Flow

```
External Client <-> Transport Plugin <-> Orchestrator <-> Plugins
```

## Details

TODO: Document the external protocol supported by this transport.
