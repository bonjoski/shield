package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/bonjoski/shield/pkg/gateway"
	"github.com/bonjoski/shield/pkg/proxy"
)

func parseGatewayConfig(args []string) (gateway.Config, string, error) {
	fs := flag.NewFlagSet("gateway", flag.ContinueOnError)
	listenAddr := fs.String("listen", gateway.DefaultListenAddr, "TCP address to bind (must be loopback, e.g. 127.0.0.1:8080)")
	upstreamURL := fs.String("upstream", gateway.DefaultUpstreamURL, "Upstream AI model provider API URL (e.g. https://api.openai.com/v1)")
	vaultSecret := fs.String("vault-secret", gateway.DefaultVaultSecret, "Locksmith vault secret name to retrieve on demand (e.g. openai/api-key)")
	socketPath := fs.String("socket", "", "Unix domain socket path to bind for local IPC (optional)")
	authToken := fs.String("auth-token", "", "Optional client authentication token required for incoming requests")
	locksmithSocket := fs.String("locksmith-socket", "", "Optional custom path to Locksmith daemon Unix domain socket")
	pidFile := fs.String("pid-file", "", "Optional path to write PID file")

	if err := fs.Parse(args); err != nil {
		return gateway.Config{}, "", err
	}

	cfg := gateway.Config{
		ListenAddr:      *listenAddr,
		UpstreamURL:     *upstreamURL,
		VaultSecret:     *vaultSecret,
		SocketPath:      *socketPath,
		AuthToken:       *authToken,
		LocksmithSocket: *locksmithSocket,
	}
	return cfg, *pidFile, nil
}

func runGateway(args []string) {
	cfg, pidFile, err := parseGatewayConfig(args)
	if err != nil {
		os.Exit(1)
	}

	srv, err := gateway.NewServer(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[SHIELD GATEWAY] Configuration error: %v\n", err)
		os.Exit(1)
	}

	if err := srv.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "[SHIELD GATEWAY] Failed to start gateway: %v\n", err)
		os.Exit(1)
	}

	if pidFile != "" {
		expandedPID := proxy.ExpandPath(pidFile)
		if err := writePIDFileSafely(expandedPID); err != nil {
			fmt.Fprintf(os.Stderr, "[SHIELD GATEWAY] Warning: failed to write PID file %s: %v\n", expandedPID, err)
		} else {
			defer removePIDFileSafely(expandedPID)
		}
	}

	if cfg.SocketPath != "" {
		expandedSock := gateway.ExpandPath(cfg.SocketPath)
		fmt.Printf("[SHIELD GATEWAY] Keyless AI Gateway Adapter active on unix socket: %s\n", expandedSock)
		fmt.Printf("[SHIELD GATEWAY] Upstream Provider: %s | Vault Secret: %s\n", cfg.UpstreamURL, cfg.VaultSecret)
		fmt.Printf("[SHIELD GATEWAY] Local socket mode active. Zero open TCP network ports.\n")
	} else {
		fmt.Printf("[SHIELD GATEWAY] Keyless AI Gateway Adapter active on: %s\n", cfg.ListenAddr)
		fmt.Printf("[SHIELD GATEWAY] Upstream Provider: %s | Vault Secret: %s\n", cfg.UpstreamURL, cfg.VaultSecret)
		fmt.Printf("[SHIELD GATEWAY] Configure LiteLLM / Dify api_base: http://%s/v1\n", cfg.ListenAddr)
	}

	if cfg.AuthToken != "" {
		fmt.Printf("[SHIELD GATEWAY] Client authentication token enforced.\n")
	} else {
		fmt.Printf("[SHIELD GATEWAY] Open local client mode (pass-through session tokens permitted).\n")
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	<-sigCh

	fmt.Println("\n[SHIELD GATEWAY] Shutting down gateway...")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := srv.Stop(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "[SHIELD GATEWAY] Warning: shutdown error: %v\n", err)
	}
}
