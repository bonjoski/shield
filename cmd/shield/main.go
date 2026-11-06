package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/bonjoski/shield/pkg/dbguard"
	"github.com/bonjoski/shield/pkg/provider"
	"github.com/bonjoski/shield/pkg/proxy"
	"github.com/bonjoski/shield/pkg/shield"
	"github.com/bonjoski/shield/pkg/status"
	"github.com/bonjoski/shield/pkg/version"
)

type stringSliceFlag []string

func (s *stringSliceFlag) String() string {
	if s == nil {
		return ""
	}
	return strings.Join(*s, ",")
}

func (s *stringSliceFlag) Set(val string) error {
	for _, part := range strings.Split(val, ",") {
		trimmed := strings.TrimSpace(part)
		if trimmed != "" {
			*s = append(*s, trimmed)
		}
	}
	return nil
}

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	cmd := os.Args[1]

	switch cmd {
	case "proxy":
		runProxy(os.Args[2:])
	case "status":
		runStatus(os.Args[2:])
	case "db":
		runDB(os.Args[2:])
	case "redact":
		runRedact(os.Args[2:])
	case "version", "--version", "-v":
		fmt.Printf("shield %s (bonjoski sovereign BYO-AI shield)\n", version.Version)
		os.Exit(0)
	case "help", "--help", "-h":
		printUsage()
		os.Exit(0)
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
             --addr <addr>              TCP address to bind (default: 127.0.0.1:8080)
             --socket <path>            Unix domain socket path (e.g. ~/.shield/shield.sock)
             --pid-file <path>          Path to write PID file (default: ~/.shield/shield.pid)
             --tls                      Enable trusted HTTPS listener
             --cert <path>              Server TLS certificate (default: ~/.locksmith/certs/server.crt)
             --key <path>               Server TLS private key (default: ~/.locksmith/certs/server.key)
             --client-ca <path>         Client CA certificate for mTLS mutual verification
             --allowed-spiffe-id <id>   Allowed SPIFFE ID or wildcard pattern (repeatable or comma-separated)
             --spiffe-acl <ids>         Comma-separated list of allowed SPIFFE IDs or wildcard patterns
             --provider <name>          AI Provider (gemini, claude, openai, ollama, mock)
             --model <model>            Model override
  status   Check running status and health of the Shield proxy daemon
           Flags:
             --addr <addr>              TCP address to check (default: 127.0.0.1:8443, 127.0.0.1:8080)
             --socket <path>            Unix domain socket path to check (default: ~/.shield/shield.sock)
             --pid-file <path>          Path to PID file (default: ~/.shield/shield.pid)
             --json                     Output status report as JSON
             --timeout <duration>       Health probe timeout (default: 1s)
  db       Manage the database capability wire guard (PostgreSQL AST policy & entropy filter)
           Subcommands:
             proxy                      Run transparent PostgreSQL wire proxy on UDS or TCP
             inspect                    Inspect an SQL query against security policy offline
  redact   Scrub and tokenize secrets from a text stream or file
  version  Print shield version`)
}

func runProxy(args []string) {
	fs := flag.NewFlagSet("proxy", flag.ExitOnError)
	addr := fs.String("addr", "127.0.0.1:8080", "TCP address to bind proxy server (when not using --socket)")
	socket := fs.String("socket", "", "Unix domain socket path to bind (e.g. ~/.shield/shield.sock)")
	pidFile := fs.String("pid-file", proxy.DefaultPIDPath(), "Path to write PID file")
	tlsEnabled := fs.Bool("tls", false, "Enable HTTPS / TLS listener")
	cert := fs.String("cert", "", "Path to TLS server certificate PEM (defaults to ~/.locksmith/certs/server.crt if exists)")
	key := fs.String("key", "", "Path to TLS server private key PEM (defaults to ~/.locksmith/certs/server.key if exists)")
	clientCA := fs.String("client-ca", "", "Path to Client CA certificate PEM for mTLS verification")
	var allowedSPIFFEIDs stringSliceFlag
	fs.Var(&allowedSPIFFEIDs, "allowed-spiffe-id", "Allowed SPIFFE ID or wildcard pattern (repeatable or comma-separated)")
	fs.Var(&allowedSPIFFEIDs, "spiffe-acl", "Comma-separated list of allowed SPIFFE IDs or wildcard patterns")
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
		Addr:             *addr,
		SocketPath:       *socket,
		TLS:              *tlsEnabled,
		CertFile:         *cert,
		KeyFile:          *key,
		ClientCA:         *clientCA,
		AllowedSPIFFEIDs: allowedSPIFFEIDs,
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
		if len(opts.AllowedSPIFFEIDs) > 0 {
			fmt.Printf("[SHIELD] SPIFFE client certificate authorization active (%d allowed pattern(s))\n", len(opts.AllowedSPIFFEIDs))
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

	if *pidFile != "" {
		expandedPID := proxy.ExpandPath(*pidFile)
		if dir := filepath.Dir(expandedPID); dir != "" {
			_ = os.MkdirAll(dir, 0700)
		}
		_ = os.WriteFile(expandedPID, []byte(fmt.Sprintf("%d\n", os.Getpid())), 0600)
		defer func() {
			_ = os.Remove(expandedPID)
		}()
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	<-sigCh

	fmt.Println("\n[SHIELD] Shutting down proxy...")
	_ = srv.Stop(context.Background())
}

func runStatus(args []string) {
	fs := flag.NewFlagSet("status", flag.ExitOnError)
	addr := fs.String("addr", "", "TCP address to check (default: 127.0.0.1:8443, 127.0.0.1:8080)")
	socket := fs.String("socket", "", "Unix domain socket path to check (default: ~/.shield/shield.sock)")
	pidFile := fs.String("pid-file", "", "Path to PID file (default: ~/.shield/shield.pid)")
	jsonOutput := fs.Bool("json", false, "Output status report as JSON")
	timeoutStr := fs.String("timeout", "1s", "Health probe timeout")
	_ = fs.Parse(args)

	timeout, err := time.ParseDuration(*timeoutStr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Invalid timeout duration %q: %v\n", *timeoutStr, err)
		os.Exit(1)
	}

	opts := status.Options{
		Addr:       *addr,
		SocketPath: *socket,
		PIDFile:    *pidFile,
		Timeout:    timeout,
	}

	info, err := status.Probe(context.Background(), opts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Status check error: %v\n", err)
		os.Exit(1)
	}

	if *jsonOutput {
		jsonStr, err := info.FormatJSON()
		if err != nil {
			fmt.Fprintf(os.Stderr, "JSON formatting error: %v\n", err)
			os.Exit(1)
		}
		fmt.Println(jsonStr)
	} else {
		fmt.Print(info.FormatHuman())
	}
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

func runDB(args []string) {
	if len(args) == 0 {
		printDBUsage()
		os.Exit(1)
	}

	subcmd := args[0]
	switch subcmd {
	case "proxy":
		runDBProxy(args[1:])
	case "inspect":
		runDBInspect(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "Unknown db subcommand: %s\n", subcmd)
		printDBUsage()
		os.Exit(1)
	}
}

func printDBUsage() {
	fmt.Println(`Usage: shield db <subcommand> [flags]

Subcommands:
  proxy     Start transparent PostgreSQL wire guard proxy (Unix Domain Socket or TCP)
            Flags:
              --listen <addr|path>      Listen address or Unix domain socket (default: /tmp/shield-db.sock)
              --upstream <addr>         Upstream PostgreSQL address (default: 127.0.0.1:5432)
              --row-limit <int>         Maximum row limit to enforce on open SELECTs (default: 100)
              --entropy-threshold <f>   Shannon entropy threshold in bits/byte (default: 5.0)
              --require-token           Require Conjoiner task token for database connections
  inspect   Evaluate SQL query against AST policy offline
            Flags:
              --row-limit <int>         Maximum row limit to test (default: 100)
              <sql>                     SQL query string (or read from stdin if omitted)`)
}

func runDBProxy(args []string) {
	fs := flag.NewFlagSet("shield db proxy", flag.ExitOnError)
	listenAddr := fs.String("listen", "/tmp/shield-db.sock", "Listen address (Unix domain socket path or TCP host:port)")
	upstreamAddr := fs.String("upstream", "127.0.0.1:5432", "Upstream PostgreSQL address (host:port or socket path)")
	rowLimit := fs.Int("row-limit", 100, "Maximum row limit to enforce on open SELECTs")
	entropyThreshold := fs.Float64("entropy-threshold", 5.0, "Shannon entropy threshold (bits/byte) for result row inspection")
	requireToken := fs.Bool("require-token", false, "Require Conjoiner task token on connections")
	_ = fs.Parse(args)

	pol := dbguard.Policy{
		BlockDDL:                    true,
		BlockUnconstrainedMutations: true,
		BlockPrivilegeEscalation:    true,
		EnforceRowLimit:             int64(*rowLimit),
		RequireConjoinerToken:       *requireToken,
		EntropyLimit:                *entropyThreshold,
	}

	filter := dbguard.NewEngine(pol, dbguard.NewDefaultTokenVerifier(true))
	scanner := dbguard.NewScanner(*entropyThreshold)

	srv, err := dbguard.NewServer(dbguard.Config{
		ListenAddr:     *listenAddr,
		UpstreamAddr:   *upstreamAddr,
		Filter:         filter,
		EntropyScanner: scanner,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "[SHIELD-DB] Configuration error: %v\n", err)
		os.Exit(1)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		if err := srv.Start(ctx); err != nil && ctx.Err() == nil {
			fmt.Fprintf(os.Stderr, "[SHIELD-DB] Failed to start database wire proxy: %v\n", err)
			os.Exit(1)
		}
	}()

	fmt.Printf("[SHIELD-DB] Database wire guard proxy active on %s (upstream: %s)\n", *listenAddr, *upstreamAddr)
	fmt.Printf("[SHIELD-DB] Policy: DDL=BLOCKED, UnconstrainedMutations=BLOCKED, RowLimit=%d, EntropyThreshold=%.1f\n", *rowLimit, *entropyThreshold)

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	<-sigCh

	fmt.Println("\n[SHIELD-DB] Shutting down database wire guard...")
	cancel()
	_ = srv.Close()
}

func runDBInspect(args []string) {
	fs := flag.NewFlagSet("shield db inspect", flag.ExitOnError)
	rowLimit := fs.Int("row-limit", 100, "Row limit to enforce on open SELECTs")
	_ = fs.Parse(args)

	var sql string
	remaining := fs.Args()
	if len(remaining) > 0 {
		sql = strings.Join(remaining, " ")
	} else {
		inputBytes, err := io.ReadAll(os.Stdin)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading stdin: %v\n", err)
			os.Exit(1)
		}
		sql = string(inputBytes)
	}

	if strings.TrimSpace(sql) == "" {
		fmt.Fprintln(os.Stderr, "Error: No SQL query provided")
		os.Exit(1)
	}

	pol := dbguard.Policy{
		BlockDDL:                    true,
		BlockUnconstrainedMutations: true,
		BlockPrivilegeEscalation:    true,
		EnforceRowLimit:             int64(*rowLimit),
		RequireConjoinerToken:       false,
		EntropyLimit:                5.0,
	}

	filter := dbguard.NewEngine(pol, dbguard.NewDefaultTokenVerifier(true))
	verdict, err := filter.InspectQuery(context.Background(), "", sql)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Inspection failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Action: %s\n", verdict.Action)
	if verdict.Reason != "" {
		fmt.Printf("Reason: %s\n", verdict.Reason)
	}
	if verdict.RewrittenSQL != "" && verdict.RewrittenSQL != sql {
		fmt.Printf("Rewritten SQL:\n%s\n", verdict.RewrittenSQL)
	}
	if verdict.Action == dbguard.ActionBlock {
		os.Exit(2)
	}
}
