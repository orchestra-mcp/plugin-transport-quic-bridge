// Command transport-quic-bridge is the entry point for the transport.quic-bridge
// plugin. It listens for remote QUIC client connections (desktop/mobile apps) and
// forwards JSON-RPC 2.0 requests to the Orchestra orchestrator over QUIC+mTLS.
//
// Configuration via flags or environment variables:
//
//	transport-quic-bridge \
//	  --orchestrator-addr localhost:9100 \   # or ORCHESTRA_ORCHESTRATOR_ADDR
//	  --listen-addr :9200 \                 # or ORCHESTRA_LISTEN_ADDR
//	  --certs-dir ~/.orchestra/certs \      # or ORCHESTRA_CERTS_DIR
//	  --api-key my-secret-key               # or ORCHESTRA_API_KEY
package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/orchestra-mcp/plugin-transport-quic-bridge/internal"
	"github.com/orchestra-mcp/sdk-go/plugin"
)

// envOrDefault returns the environment variable value if set, otherwise the
// default value. This allows all flags to be configured via env vars.
func envOrDefault(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func main() {
	orchestratorAddr := flag.String("orchestrator-addr",
		envOrDefault("ORCHESTRA_ORCHESTRATOR_ADDR", "localhost:9100"),
		"Address of the orchestrator (env: ORCHESTRA_ORCHESTRATOR_ADDR)")
	listenAddr := flag.String("listen-addr",
		envOrDefault("ORCHESTRA_LISTEN_ADDR", ":9200"),
		"Address to listen for remote QUIC client connections (env: ORCHESTRA_LISTEN_ADDR)")
	certsDir := flag.String("certs-dir",
		envOrDefault("ORCHESTRA_CERTS_DIR", plugin.DefaultCertsDir),
		"Directory for mTLS certificates (env: ORCHESTRA_CERTS_DIR)")
	apiKey := flag.String("api-key",
		envOrDefault("ORCHESTRA_API_KEY", ""),
		"Static API key for client authentication, empty = no auth (env: ORCHESTRA_API_KEY)")
	flag.Parse()

	if *orchestratorAddr == "" {
		log.Fatal("--orchestrator-addr is required")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		fmt.Fprintf(os.Stderr, "transport.quic-bridge: received shutdown signal\n")
		cancel()
	}()

	// Resolve the certs directory (expand ~ if present).
	resolvedCertsDir := plugin.ResolveCertsDir(*certsDir)

	// Set up mTLS client configuration for connecting to the orchestrator.
	clientTLS, err := plugin.ClientTLSConfig(resolvedCertsDir, "transport.quic-bridge-client")
	if err != nil {
		log.Fatalf("client TLS config: %v", err)
	}

	// Connect to the orchestrator over QUIC.
	client, err := plugin.NewOrchestratorClient(ctx, *orchestratorAddr, clientTLS)
	if err != nil {
		log.Fatalf("connect to orchestrator at %s: %v", *orchestratorAddr, err)
	}
	defer client.Close()

	fmt.Fprintf(os.Stderr, "transport.quic-bridge: connected to orchestrator at %s\n", *orchestratorAddr)

	// Set up TLS server configuration for accepting remote QUIC clients.
	caCert, caKey, err := plugin.EnsureCA(resolvedCertsDir)
	if err != nil {
		log.Fatalf("ensure CA: %v", err)
	}

	serverCert, err := plugin.GenerateCert(resolvedCertsDir, "quic-bridge-server", caCert, caKey)
	if err != nil {
		log.Fatalf("generate server cert: %v", err)
	}

	serverTLS := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		NextProtos:   []string{"orchestra-bridge"},
		MinVersion:   tls.VersionTLS13,
	}

	// Create the QUIC bridge and start serving.
	bridge := internal.NewBridge(client, *apiKey)

	fmt.Fprintf(os.Stderr, "transport.quic-bridge: QUIC listening on %s\n", *listenAddr)

	if err := bridge.ListenAndServe(ctx, *listenAddr, serverTLS); err != nil {
		if ctx.Err() != nil {
			fmt.Fprintf(os.Stderr, "transport.quic-bridge: shutting down\n")
			return
		}
		log.Fatalf("transport.quic-bridge: %v", err)
	}
}
