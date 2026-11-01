package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/bonjoski/shield/pkg/provider"
	"github.com/bonjoski/shield/pkg/proxy"
	"github.com/bonjoski/shield/pkg/shield"
	"github.com/bonjoski/shield/pkg/version"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	cmd := os.Args[1]

	switch cmd {
	case "proxy":
		runProxy(os.Args[2:])
	case "redact":
		runRedact(os.Args[2:])
	case "version":
		fmt.Printf("shield %s (bonjoski sovereign BYO-AI shield)\n", version.Version)
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n", cmd)
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println(`Usage: shield <command> [flags]

Commands:
  proxy    Start the client-side secret shield loopback proxy (for Cursor, Claude Code, Antigravity)
           Flags:
             --addr <addr>        TCP address to bind (default: 127.0.0.1:8080)
             --socket <path>      Unix domain socket path (e.g. ~/.shield/shield.sock)
             --tls                Enable trusted HTTPS listener
             --cert <path>        Server TLS certificate (default: ~/.locksmith/certs/server.crt)
             --key <path>         Server TLS private key (default: ~/.locksmith/certs/server.key)
             --client-ca <path>   Client CA certificate for mTLS mutual verification
             --provider <name>    AI Provider (gemini, claude, openai, ollama, mock)
             --model <model>      Model override
  redact   Scrub and tokenize secrets from a text stream or file
  version  Print shield version`)
}

func runProxy(args []string) {
	fs := flag.NewFlagSet("proxy", flag.ExitOnError)
	addr := fs.String("addr", "127.0.0.1:8080", "TCP address to bind proxy server (when not using --socket)")
	socket := fs.String("socket", "", "Unix domain socket path to bind (e.g. ~/.shield/shield.sock)")
	tlsEnabled := fs.Bool("tls", false, "Enable HTTPS / TLS listener")
	cert := fs.String("cert", "", "Path to TLS server certificate PEM (defaults to ~/.locksmith/certs/server.crt if exists)")
	key := fs.String("key", "", "Path to TLS server private key PEM (defaults to ~/.locksmith/certs/server.key if exists)")
	clientCA := fs.String("client-ca", "", "Path to Client CA certificate PEM for mTLS verification")
	providerName := fs.String("provider", "mock", "AI Provider to route to (gemini, claude, openai, ollama, mock)")
	model := fs.String("model", "", "Model name override")
	_ = fs.Parse(args)

	var prov provider.Provider
	switch *providerName {
	case "gemini":
		prov = provider.NewGeminiProvider(os.Getenv("GEMINI_API_KEY"), *model)
	case "claude":
		prov = provider.NewClaudeProvider(os.Getenv("ANTHROPIC_API_KEY"), *model)
	case "openai":
		prov = provider.NewOpenAIProvider(os.Getenv("OPENAI_API_KEY"), *model, os.Getenv("OPENAI_BASE_URL"))
	case "ollama":
		prov = provider.NewOllamaProvider(os.Getenv("OLLAMA_BASE_URL"), *model)
	default:
		prov = provider.NewMockProvider("mock-ai", "Shield loopback proxy response.")
	}

	opts := proxy.Options{
		Addr:       *addr,
		SocketPath: *socket,
		TLS:        *tlsEnabled,
		CertFile:   *cert,
		KeyFile:    *key,
		ClientCA:   *clientCA,
	}

	if *cert != "" || *key != "" {
		opts.TLS = true
	}

	if opts.SocketPath == "" && !opts.TLS {
		defaultCert := proxy.DefaultCertPath()
		defaultKey := proxy.DefaultKeyPath()
		if _, err1 := os.Stat(defaultCert); err1 == nil {
			if _, err2 := os.Stat(defaultKey); err2 == nil {
				fmt.Println("[SHIELD] [INFO] Locksmith root-anchored certificates found at ~/.locksmith/certs/server.crt. Use --tls to activate trusted HTTPS.")
			}
		}
	}

	engine := shield.NewEngine(shield.DefaultConfig())
	srv := proxy.NewServerWithOptions(opts, engine, prov)

	if opts.SocketPath != "" {
		expandedSock := proxy.ExpandPath(opts.SocketPath)
		fmt.Printf("[SHIELD] Starting sovereign BYO-AI Unix socket proxy on %s (upstream: %s)...\n", expandedSock, prov.Name())
		fmt.Printf("[SHIELD] Unix domain socket mode active. No open TCP/HTTP network ports.\n")
		fmt.Printf("[SHIELD] For socket-compatible clients: curl --unix-socket %s http://localhost/v1/...\n", expandedSock)
	} else if opts.TLS {
		fmt.Printf("[SHIELD] Starting sovereign BYO-AI HTTPS proxy on %s (upstream: %s)...\n", *addr, prov.Name())
		fmt.Printf("[SHIELD] In Cursor / Claude Code, set Base URL to: https://%s/v1\n", *addr)
		if opts.ClientCA != "" {
			fmt.Printf("[SHIELD] mTLS Client Certificate verification active (CA: %s)\n", opts.ClientCA)
		}
	} else {
		fmt.Printf("[SHIELD] Starting sovereign BYO-AI HTTP loopback proxy on %s (upstream: %s)...\n", *addr, prov.Name())
		fmt.Printf("[SHIELD] [WARNING] Plaintext HTTP active. For zero-trust local isolation, use --socket or --tls.\n")
		fmt.Printf("[SHIELD] In Cursor / Claude Code, set Base URL to: http://%s/v1\n", *addr)
	}

	if err := srv.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to start proxy: %v\n", err)
		os.Exit(1)
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	<-sigCh

	fmt.Println("\n[SHIELD] Shutting down proxy...")
	_ = srv.Stop(context.Background())
}

func runRedact(args []string) {
	fs := flag.NewFlagSet("redact", flag.ExitOnError)
	inputFile := fs.String("input", "-", "Input file or '-' for stdin")
	_ = fs.Parse(args)

	var inputBytes []byte
	var err error

	if *inputFile == "-" {
		inputBytes, err = io.ReadAll(os.Stdin)
	} else {
		inputBytes, err = os.ReadFile(*inputFile)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading input: %v\n", err)
		os.Exit(1)
	}

	engine := shield.NewEngine(shield.DefaultConfig())
	redacted, tm, err := engine.Redact(string(inputBytes))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Redaction error: %v\n", err)
		os.Exit(1)
	}

	fmt.Println(redacted)
	fmt.Fprintf(os.Stderr, "[SHIELD] Redacted %d unique secret(s).\n", tm.Count())
}
