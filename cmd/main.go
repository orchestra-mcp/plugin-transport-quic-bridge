// Command transport-quic-bridge is the entry point for the transport.quic-bridge
// plugin. It listens for remote QUIC client connections (desktop/mobile/web) and
// forwards JSON-RPC 2.0 requests to the Orchestra orchestrator over QUIC.
//
// Unlike transport-stdio (which reads from stdin/stdout), this plugin exposes a
// network-accessible QUIC endpoint that remote clients connect to.
//
// Usage:
//
//	transport-quic-bridge \
//	  --orchestrator-addr localhost:9100 \
//	  --listen-addr :9200 \
//	  --certs-dir ~/.orchestra/certs \
//	  --api-key my-secret-key
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

func main() {
	orchestratorAddr := flag.String("orchestrator-addr", "localhost:9100", "Address of the orchestrator")
	listenAddr := flag.String("listen-addr", ":9200", "Address to listen for remote client connections")
	certsDir := flag.String("certs-dir", plugin.DefaultCertsDir, "Directory for mTLS certificates")
	apiKey := flag.String("api-key", "", "Static API key for client authentication (empty = no auth)")
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

	// Set up TLS server configuration for accepting remote clients.
	// This is regular TLS (NOT mTLS) since remote clients do not have Orchestra
	// CA certificates. The server presents its certificate; clients only need to
	// trust the CA or skip verification for local development.
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

	// Create the bridge and start serving.
	bridge := internal.NewBridge(client, *apiKey)

	fmt.Fprintf(os.Stderr, "transport.quic-bridge: listening for remote clients on %s\n", *listenAddr)

	if err := bridge.ListenAndServe(ctx, *listenAddr, serverTLS); err != nil {
		if ctx.Err() != nil {
			fmt.Fprintf(os.Stderr, "transport.quic-bridge: shutting down\n")
			return
		}
		log.Fatalf("transport.quic-bridge: %v", err)
	}
}
