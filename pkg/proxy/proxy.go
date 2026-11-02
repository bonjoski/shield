package proxy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/bonjoski/shield/pkg/provider"
	"github.com/bonjoski/shield/pkg/reassembly"
	"github.com/bonjoski/shield/pkg/shield"
)

var (
	// ErrSymlinkDetected is returned when the configured socket path is a symlink.
	ErrSymlinkDetected = errors.New("security violation: socket path is a symlink")
	// ErrAlreadyRunning is returned when Start() is called on an already active server.
	ErrAlreadyRunning = errors.New("proxy server is already running")
)

// Options configures the proxy server listeners and security parameters.
type Options struct {
	Addr             string   // TCP address to bind (e.g. "127.0.0.1:8080" or "127.0.0.1:8443")
	SocketPath       string   // Unix domain socket path (e.g. "~/.shield/shield.sock")
	TLS              bool     // Enable TLS / HTTPS listener
	CertFile         string   // Path to server certificate PEM
	KeyFile          string   // Path to server private key PEM
	ClientCA         string   // Path to client CA PEM for mTLS client verification
	AllowedSPIFFEIDs []string // Allowed SPIFFE IDs or wildcard patterns (e.g. "spiffe://bonjoski.local/ns/dev/*")
}

// Server implements a local loopback reverse proxy providing client-side secret shielding
// for developer AI clients like Cursor, Windsurf, Claude Code, and Antigravity.
type Server struct {
	opts        Options
	engine      *shield.Engine
	prov        provider.Provider
	reassembler *reassembly.Reassembler
	httpServer  *http.Server
	listener    net.Listener
	mu          sync.Mutex
	running     bool
}

// ExpandPath expands a leading ~ to the user's home directory.
func ExpandPath(p string) string {
	if p == "" {
		return ""
	}
	if p == "~" {
		home, err := os.UserHomeDir()
		if err == nil {
			return home
		}
	} else if strings.HasPrefix(p, "~/") {
		home, err := os.UserHomeDir()
		if err == nil {
			return filepath.Join(home, p[2:])
		}
	}
	return p
}

// DefaultCertPath returns the standard Locksmith server certificate path.
func DefaultCertPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".locksmith", "certs", "server.crt")
}

// DefaultKeyPath returns the standard Locksmith server key path.
func DefaultKeyPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".locksmith", "certs", "server.key")
}

// DefaultSocketPath returns the standard Shield Unix domain socket path.
func DefaultSocketPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".shield", "shield.sock")
}

// NewServer initializes a proxy server using default TCP options.
func NewServer(addr string, engine *shield.Engine, prov provider.Provider) *Server {
	if addr == "" {
		addr = "127.0.0.1:8080"
	}
	return NewServerWithOptions(Options{Addr: addr}, engine, prov)
}

// NewServerWithOptions initializes a proxy server with custom network and TLS options.
func NewServerWithOptions(opts Options, engine *shield.Engine, prov provider.Provider) *Server {
	if opts.SocketPath == "" && opts.Addr == "" {
		opts.Addr = "127.0.0.1:8080"
	}
	return &Server{
		opts:        opts,
		engine:      engine,
		prov:        prov,
		reassembler: reassembly.NewReassembler(),
	}
}

// ListenerAddr returns the actual listening network address.
func (s *Server) ListenerAddr() net.Addr {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.listener != nil {
		return s.listener.Addr()
	}
	return nil
}

// Options returns a copy of the server configuration options.
func (s *Server) Options() Options {
	return s.opts
}

// Start launches the loopback HTTP/HTTPS or Unix socket server in the background.
func (s *Server) Start() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.running {
		return ErrAlreadyRunning
	}

	mux := http.NewServeMux()
	mux.Handle("/v1/chat/completions", s.authorizeSPIFFE(http.HandlerFunc(s.handleOpenAI)))
	mux.Handle("/v1/messages", s.authorizeSPIFFE(http.HandlerFunc(s.handleAnthropic)))
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"healthy","shield":"active"}`))
	})

	s.httpServer = &http.Server{
		Handler:      mux,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 90 * time.Second,
	}

	var l net.Listener
	var err error

	if s.opts.SocketPath != "" {
		sockPath := ExpandPath(s.opts.SocketPath)

		// Prevent symlink hijacking
		if fi, lerr := os.Lstat(sockPath); lerr == nil {
			if fi.Mode()&os.ModeSymlink != 0 {
				return ErrSymlinkDetected
			}
			// Safe to remove existing regular/socket file
			if err := os.Remove(sockPath); err != nil {
				return fmt.Errorf("failed to remove existing socket file: %w", err)
			}
		}

		// Ensure parent directory exists with 0700 permissions
		dir := filepath.Dir(sockPath)
		if err := os.MkdirAll(dir, 0700); err != nil {
			return fmt.Errorf("failed to create socket directory: %w", err)
		}

		l, err = net.Listen("unix", sockPath)
		if err != nil {
			return fmt.Errorf("failed to listen on unix socket %s: %w", sockPath, err)
		}

		// Strict permissions: 0600 (read/write only by owner)
		if err := os.Chmod(sockPath, 0600); err != nil {
			_ = l.Close()
			_ = os.Remove(sockPath)
			return fmt.Errorf("failed to set socket permissions: %w", err)
		}
	} else {
		l, err = net.Listen("tcp", s.opts.Addr)
		if err != nil {
			return fmt.Errorf("failed to listen on tcp addr %s: %w", s.opts.Addr, err)
		}
	}

	// Configure TLS if explicitly enabled or if cert/key paths are provided
	if s.opts.TLS || s.opts.CertFile != "" || s.opts.KeyFile != "" {
		certFile := ExpandPath(s.opts.CertFile)
		keyFile := ExpandPath(s.opts.KeyFile)

		if certFile == "" {
			certFile = DefaultCertPath()
		}
		if keyFile == "" {
			keyFile = DefaultKeyPath()
		}

		tlsCert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			_ = l.Close()
			if s.opts.SocketPath != "" {
				_ = os.Remove(ExpandPath(s.opts.SocketPath))
			}
			return fmt.Errorf("failed to load TLS keypair (%s, %s): %w", certFile, keyFile, err)
		}

		tlsConfig := &tls.Config{
			Certificates: []tls.Certificate{tlsCert},
			MinVersion:   tls.VersionTLS12,
			CurvePreferences: []tls.CurveID{
				tls.X25519MLKEM768,
				tls.SecP256r1MLKEM768,
				tls.SecP384r1MLKEM1024,
				tls.X25519,
				tls.CurveP256,
				tls.CurveP384,
			},
			PreferServerCipherSuites: true,
		}

		if s.opts.ClientCA != "" {
			clientCAPath := ExpandPath(s.opts.ClientCA)
			caData, err := os.ReadFile(clientCAPath)
			if err != nil {
				_ = l.Close()
				if s.opts.SocketPath != "" {
					_ = os.Remove(ExpandPath(s.opts.SocketPath))
				}
				return fmt.Errorf("failed to read client CA (%s): %w", clientCAPath, err)
			}
			clientPool := x509.NewCertPool()
			if !clientPool.AppendCertsFromPEM(caData) {
				_ = l.Close()
				if s.opts.SocketPath != "" {
					_ = os.Remove(ExpandPath(s.opts.SocketPath))
				}
				return fmt.Errorf("failed to parse client CA certificates from %s", clientCAPath)
			}
			tlsConfig.ClientCAs = clientPool
			tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
		} else if len(s.opts.AllowedSPIFFEIDs) > 0 {
			// Request client certificates when SPIFFE ACL is active without explicit ClientCA
			tlsConfig.ClientAuth = tls.RequestClientCert
		}

		l = tls.NewListener(l, tlsConfig)
	}

	s.listener = l
	s.running = true

	go func() {
		_ = s.httpServer.Serve(l)
	}()

	return nil
}

// Stop gracefully shuts down the proxy server and removes socket files.
func (s *Server) Stop(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.running || s.httpServer == nil {
		return nil
	}
	s.running = false
	err := s.httpServer.Shutdown(ctx)
	if s.opts.SocketPath != "" {
		sockPath := ExpandPath(s.opts.SocketPath)
		if fi, lerr := os.Lstat(sockPath); lerr == nil && fi.Mode()&os.ModeSymlink == 0 {
			_ = os.Remove(sockPath)
		}
	}
	return err
}

func (s *Server) handleOpenAI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read request body", http.StatusBadRequest)
		return
	}

	var reqPayload struct {
		Model    string `json:"model"`
		Messages []struct {
			Role    string `json:"role"`
			Content string `json:"content"`
		} `json:"messages"`
	}

	if err := json.Unmarshal(body, &reqPayload); err != nil {
		http.Error(w, "Invalid JSON payload", http.StatusBadRequest)
		return
	}

	tm := shield.NewTokenMap()
	provMessages := make([]provider.Message, 0, len(reqPayload.Messages))

	// 1. Redact secrets from each user/system message content
	for _, m := range reqPayload.Messages {
		redactedContent, msgTM, err := s.engine.Redact(m.Content)
		if err != nil {
			http.Error(w, fmt.Sprintf("Shield redaction error: %v", err), http.StatusInternalServerError)
			return
		}

		// Merge tokens
		for _, ref := range msgTM.References() {
			sec, _ := msgTM.GetSecret(ref)
			tm.Add(sec, "")
		}

		// 2. Fail-Closed Wire Guard check
		if err := s.engine.FailClosedWireGuard([]byte(redactedContent)); err != nil {
			http.Error(w, fmt.Sprintf("Security violation: %v", err), http.StatusForbidden)
			return
		}

		provMessages = append(provMessages, provider.Message{
			Role:    m.Role,
			Content: redactedContent,
		})
	}

	// 3. Dispatch to pluggable provider
	resp, err := s.prov.Complete(r.Context(), provider.Request{
		Model:    reqPayload.Model,
		Messages: provMessages,
	})
	if err != nil {
		http.Error(w, fmt.Sprintf("Upstream AI error: %v", err), http.StatusBadGateway)
		return
	}

	// 4. Verify unmapped tokens
	if err := s.reassembler.CheckUnmappedPlaceholders(resp.Content, tm); err != nil {
		if errors.Is(err, reassembly.ErrUnmappedToken) {
			http.Error(w, fmt.Sprintf("Security alert: %v", err), http.StatusBadGateway)
			return
		}
	}

	// 5. Restore tokens locally (or leave sanitized depending on mode)
	restoredContent := s.engine.Restore(resp.Content, tm)

	// Format response to OpenAI schema
	openAIResp := map[string]interface{}{
		"id":      "shield-comp-1",
		"object":  "chat.completion",
		"created": time.Now().Unix(),
		"model":   resp.Model,
		"choices": []map[string]interface{}{
			{
				"index": 0,
				"message": map[string]string{
					"role":    "assistant",
					"content": restoredContent,
				},
				"finish_reason": resp.FinishReason,
			},
		},
		"usage": map[string]int{
			"prompt_tokens":     resp.Usage.InputTokens,
			"completion_tokens": resp.Usage.OutputTokens,
			"total_tokens":      resp.Usage.InputTokens + resp.Usage.OutputTokens,
		},
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Shield-Protection", "active")
	_ = json.NewEncoder(w).Encode(openAIResp)
}

func (s *Server) handleAnthropic(w http.ResponseWriter, r *http.Request) {
	// Analogous handling for Anthropic /v1/messages
	s.handleOpenAI(w, r)
}

// AuthorizeSPIFFE wraps an http.Handler with SPIFFE ID authorization checks based on AllowedSPIFFEIDs.
func (s *Server) AuthorizeSPIFFE(next http.Handler) http.Handler {
	return s.authorizeSPIFFE(next)
}

func (s *Server) authorizeSPIFFE(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if len(s.opts.AllowedSPIFFEIDs) > 0 {
			if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusForbidden)
				_ = json.NewEncoder(w).Encode(map[string]string{
					"error": "client certificate required",
				})
				return
			}

			peerCert := r.TLS.PeerCertificates[0]
			var spiffeIDs []string
			for _, u := range peerCert.URIs {
				if u != nil && strings.EqualFold(u.Scheme, "spiffe") {
					spiffeIDs = append(spiffeIDs, u.String())
				}
			}

			if len(spiffeIDs) == 0 {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusForbidden)
				_ = json.NewEncoder(w).Encode(map[string]string{
					"error": "spiffe uri san required",
				})
				return
			}

			matched := false
			for _, id := range spiffeIDs {
				if matchSPIFFEID(id, s.opts.AllowedSPIFFEIDs) {
					matched = true
					break
				}
			}

			if !matched {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusForbidden)
				_ = json.NewEncoder(w).Encode(map[string]string{
					"error":     "unauthorized spiffe id",
					"spiffe_id": spiffeIDs[0],
				})
				return
			}
		}

		next.ServeHTTP(w, r)
	})
}

// matchSPIFFEID returns true if clientID matches any pattern in patterns.
// Patterns support exact match and trailing wildcard match (e.g. "spiffe://bonjoski.local/ns/dev/*").
func matchSPIFFEID(clientID string, patterns []string) bool {
	for _, pattern := range patterns {
		pattern = strings.TrimSpace(pattern)
		if pattern == "" {
			continue
		}
		if strings.HasSuffix(pattern, "*") {
			prefix := strings.TrimSuffix(pattern, "*")
			if strings.HasPrefix(clientID, prefix) {
				return true
			}
		} else {
			if clientID == pattern {
				return true
			}
		}
	}
	return false
}
