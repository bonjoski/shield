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
  redact   Scrub and tokenize secrets from a text stream or file
  version  Print shield version`)
}

func runProxy(args []string) {
	fs := flag.NewFlagSet("proxy", flag.ExitOnError)
	addr := fs.String("addr", "127.0.0.1:8080", "Address to bind proxy server")
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

	engine := shield.NewEngine(shield.DefaultConfig())
	srv := proxy.NewServer(*addr, engine, prov)

	fmt.Printf("[SHIELD] Starting sovereign BYO-AI loopback proxy on %s (upstream: %s)...\n", *addr, prov.Name())
	fmt.Printf("[SHIELD] In Cursor / Claude Code, set Base URL to: http://%s/v1\n", *addr)

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
