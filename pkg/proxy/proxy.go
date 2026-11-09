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
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/bonjoski/shield/pkg/provider"
	"github.com/bonjoski/shield/pkg/reassembly"
	"github.com/bonjoski/shield/pkg/shield"
)

const (
	// MaxRequestBodyBytes bounds incoming client JSON payloads to 10 MiB to prevent OOM DoS.
	MaxRequestBodyBytes int64 = 10 << 20
)

var (
	// ErrSymlinkDetected is returned when the configured socket path is a symlink.
	ErrSymlinkDetected = errors.New("security violation: socket path is a symlink")
	// ErrAlreadyRunning is returned when Start() is called on an already active server.
	ErrAlreadyRunning = errors.New("proxy server is already running")
	// ErrSPIFFERequiresClientCA is returned when AllowedSPIFFEIDs is configured without mTLS ClientCA.
	ErrSPIFFERequiresClientCA = errors.New("security configuration error: AllowedSPIFFEIDs requires TLS and ClientCA (--client-ca) for verified mTLS chains")
	// ErrInvalidSPIFFEPattern is returned when an AllowedSPIFFEIDs entry is malformed.
	ErrInvalidSPIFFEPattern = errors.New("security configuration error: invalid AllowedSPIFFEIDs pattern")
)

// Options configures the proxy server listeners and security parameters.
type Options struct {
	Addr             string         // TCP address to bind (e.g. "127.0.0.1:8080" or "127.0.0.1:8443")
	SocketPath       string         // Unix domain socket path (e.g. "~/.shield/shield.sock")
	TLS              bool           // Enable TLS / HTTPS listener
	CertFile         string         // Path to server certificate PEM
	KeyFile          string         // Path to server private key PEM
	ClientCA         string         // Path to client CA PEM for mTLS client verification
	ClientCAPool     *x509.CertPool // Optional pre-parsed trusted client CA pool
	AllowedSPIFFEIDs []string       // Allowed SPIFFE IDs or wildcard patterns (e.g. "spiffe://bonjoski.local/ns/dev/*")
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

// DefaultPIDPath returns the standard Shield PID file path.
func DefaultPIDPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".shield", "shield.pid")
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

func cleanupSocketFile(sockPath string) error {
	if sockPath == "" {
		return nil
	}
	fi, err := os.Lstat(sockPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return ErrSymlinkDetected
	}
	if err := os.Remove(sockPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

func (s *Server) validateSecurityOptions() error {
	if len(s.opts.AllowedSPIFFEIDs) == 0 {
		return nil
	}

	tlsConfigured := s.opts.TLS || s.opts.CertFile != "" || s.opts.KeyFile != ""
	caConfigured := strings.TrimSpace(s.opts.ClientCA) != "" || s.opts.ClientCAPool != nil
	if !tlsConfigured || !caConfigured {
		return ErrSPIFFERequiresClientCA
	}

	validCount := 0
	for _, pat := range s.opts.AllowedSPIFFEIDs {
		pat = strings.TrimSpace(pat)
		if pat == "" {
			continue
		}
		if err := validateSPIFFEPattern(pat); err != nil {
			return fmt.Errorf("%w (%q): %w", ErrInvalidSPIFFEPattern, pat, err)
		}
		validCount++
	}
	if validCount == 0 {
		return fmt.Errorf("%w: no non-empty SPIFFE patterns configured", ErrInvalidSPIFFEPattern)
	}
	return nil
}

// Start launches the loopback HTTP/HTTPS or Unix socket server in the background.
func (s *Server) Start() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.running {
		return ErrAlreadyRunning
	}

	if err := s.validateSecurityOptions(); err != nil {
		return err
	}

	mux := http.NewServeMux()
	mux.Handle("/v1/chat/completions", s.authorizeSPIFFE(http.HandlerFunc(s.handleOpenAI)))
	mux.Handle("/v1/messages", s.authorizeSPIFFE(http.HandlerFunc(s.handleAnthropic)))
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"healthy","shield":"active"}`))
	})

	s.httpServer = &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      90 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}

	var l net.Listener
	var err error
	var expandedSock string

	if s.opts.SocketPath != "" {
		expandedSock = ExpandPath(s.opts.SocketPath)

		// Prevent symlink hijacking
		if fi, lerr := os.Lstat(expandedSock); lerr == nil {
			if fi.Mode()&os.ModeSymlink != 0 {
				return ErrSymlinkDetected
			}
			if err := os.Remove(expandedSock); err != nil {
				return fmt.Errorf("failed to remove existing socket file: %w", err)
			}
		}

		// Ensure parent directory exists with 0700 permissions
		dir := filepath.Dir(expandedSock)
		if err := os.MkdirAll(dir, 0700); err != nil {
			return fmt.Errorf("failed to create socket directory: %w", err)
		}

		l, err = net.Listen("unix", expandedSock)
		if err != nil {
			return fmt.Errorf("failed to listen on unix socket %s: %w", expandedSock, err)
		}

		// Strict permissions: 0600 (read/write only by owner)
		if err := os.Chmod(expandedSock, 0600); err != nil {
			_ = l.Close()
			if rmErr := cleanupSocketFile(expandedSock); rmErr != nil {
				return fmt.Errorf("failed to set socket permissions (%w) and cleanup failed (%w)", err, rmErr)
			}
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
			_ = cleanupSocketFile(expandedSock)
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

		if s.opts.ClientCAPool != nil {
			tlsConfig.ClientCAs = s.opts.ClientCAPool
			tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
		} else if s.opts.ClientCA != "" {
			clientCAPath := ExpandPath(s.opts.ClientCA)
			caData, err := os.ReadFile(clientCAPath)
			if err != nil {
				_ = l.Close()
				_ = cleanupSocketFile(expandedSock)
				return fmt.Errorf("failed to read client CA (%s): %w", clientCAPath, err)
			}
			clientPool := x509.NewCertPool()
			if !clientPool.AppendCertsFromPEM(caData) {
				_ = l.Close()
				_ = cleanupSocketFile(expandedSock)
				return fmt.Errorf("failed to parse client CA certificates from %s", clientCAPath)
			}
			tlsConfig.ClientCAs = clientPool
			tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
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
		if rmErr := cleanupSocketFile(ExpandPath(s.opts.SocketPath)); rmErr != nil && err == nil {
			err = rmErr
		}
	}
	return err
}

func (s *Server) handleOpenAI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, MaxRequestBodyBytes)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		var maxBytesErr *http.MaxBytesError
		if errors.As(err, &maxBytesErr) {
			http.Error(w, "Request body exceeds maximum allowed size", http.StatusRequestEntityTooLarge)
			return
		}
		http.Error(w, "Failed to read request body", http.StatusBadRequest)
		return
	}

	var rawDoc map[string]any
	if err := json.Unmarshal(body, &rawDoc); err != nil || rawDoc == nil {
		http.Error(w, "Invalid JSON payload", http.StatusBadRequest)
		return
	}

	// Share a single request-scoped TokenMap across all JSON fields/messages and zeroize on exit.
	tm := shield.NewTokenMap()
	defer tm.Zeroize()

	scrubbedVal, err := scrubJSONValue(rawDoc, "", s.engine, tm)
	if err != nil {
		http.Error(w, "Shield redaction error", http.StatusInternalServerError)
		return
	}
	scrubbedDoc, ok := scrubbedVal.(map[string]any)
	if !ok {
		http.Error(w, "Invalid JSON payload", http.StatusBadRequest)
		return
	}

	// Enforce Fail-Closed Wire Guard across the entire serialized scrubbed request payload.
	scrubbedBytes, err := json.Marshal(scrubbedDoc)
	if err != nil {
		http.Error(w, "Failed to serialize scrubbed payload", http.StatusInternalServerError)
		return
	}
	if err := s.engine.FailClosedWireGuard(scrubbedBytes); err != nil {
		http.Error(w, "Security violation: outbound payload blocked by wire guard", http.StatusForbidden)
		return
	}

	provReq, err := buildProviderRequestFromScrubbed(scrubbedDoc)
	if err != nil {
		http.Error(w, "Invalid completion request parameters", http.StatusBadRequest)
		return
	}

	// Dispatch to pluggable provider; never echo raw upstream URL/transport error strings to clients.
	resp, err := s.prov.Complete(r.Context(), provReq)
	if err != nil {
		http.Error(w, "Upstream AI error: provider request failed", http.StatusBadGateway)
		return
	}

	// Verify unmapped tokens so hallucinated [SECRET_REF_...] tokens cannot desynchronize rehydration.
	if err := s.reassembler.CheckUnmappedPlaceholders(resp.Content, tm); err != nil {
		if errors.Is(err, reassembly.ErrUnmappedToken) {
			http.Error(w, fmt.Sprintf("Security alert: %v", err), http.StatusBadGateway)
			return
		}
	}

	// Restore tokens locally
	restoredContent := s.engine.Restore(resp.Content, tm)

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
	s.handleOpenAI(w, r)
}

// AuthorizeSPIFFE wraps an http.Handler with SPIFFE ID authorization checks based on AllowedSPIFFEIDs.
func (s *Server) AuthorizeSPIFFE(next http.Handler) http.Handler {
	return s.authorizeSPIFFE(next)
}

func (s *Server) authorizeSPIFFE(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if len(s.opts.AllowedSPIFFEIDs) > 0 {
			if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 || len(r.TLS.VerifiedChains[0]) == 0 {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusForbidden)
				_ = json.NewEncoder(w).Encode(map[string]string{
					"error": "client certificate required",
				})
				return
			}

			// Inspect ONLY the cryptographically verified leaf certificate from VerifiedChains.
			leafCert := r.TLS.VerifiedChains[0][0]
			var rawSPIFFEIDs []string
			for _, u := range leafCert.URIs {
				if u != nil && u.Scheme == "spiffe" {
					rawSPIFFEIDs = append(rawSPIFFEIDs, u.String())
				}
			}

			if len(rawSPIFFEIDs) == 0 {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusForbidden)
				_ = json.NewEncoder(w).Encode(map[string]string{
					"error": "spiffe uri san required",
				})
				return
			}

			matched := false
			for _, id := range rawSPIFFEIDs {
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
					"spiffe_id": rawSPIFFEIDs[0],
				})
				return
			}
		}

		next.ServeHTTP(w, r)
	})
}

// canonicalizeSPIFFEURI validates and canonicalizes a SPIFFE ID URI (or prefix base when requirePathSegment is false),
// strictly rejecting non-spiffe:// schemes, userinfo, ports, queries, fragments, percent-encoding, empty segments, `.` and `..`.
func canonicalizeSPIFFEURI(raw string, requirePathSegment bool) (string, error) {
	if !strings.HasPrefix(raw, "spiffe://") {
		return "", errors.New("scheme must be spiffe://")
	}
	if strings.ContainsAny(raw, "?#%\\\x00 \t\r\n") {
		return "", errors.New("disallowed characters in SPIFFE URI")
	}

	u, err := url.Parse(raw)
	if err != nil {
		return "", err
	}
	if u.Scheme != "spiffe" || u.User != nil || u.Opaque != "" || u.RawQuery != "" || u.Fragment != "" {
		return "", errors.New("malformed SPIFFE URI components")
	}
	if u.Host == "" || strings.Contains(u.Host, ":") || strings.Contains(u.Host, "..") {
		return "", errors.New("invalid SPIFFE trust domain")
	}

	rest := raw[len("spiffe://")+len(u.Host):]
	if rest == "" {
		if requirePathSegment {
			return "", errors.New("workload SPIFFE ID must include non-empty path")
		}
		return "spiffe://" + strings.ToLower(u.Host), nil
	}

	if !strings.HasPrefix(rest, "/") {
		return "", errors.New("invalid SPIFFE path prefix")
	}
	if rest == "/" {
		return "", errors.New("empty trailing segment in SPIFFE path")
	}

	segments := strings.Split(rest[1:], "/")
	for _, seg := range segments {
		if seg == "" || seg == "." || seg == ".." || strings.Contains(seg, "*") {
			return "", fmt.Errorf("invalid SPIFFE path segment %q", seg)
		}
	}

	return "spiffe://" + strings.ToLower(u.Host) + "/" + strings.Join(segments, "/"), nil
}

func validateSPIFFEPattern(pattern string) error {
	if pattern == "*" {
		return nil
	}
	if strings.HasSuffix(pattern, "/*") {
		base := strings.TrimSuffix(pattern, "/*")
		_, err := canonicalizeSPIFFEURI(base, false)
		return err
	}
	if strings.Contains(pattern, "*") {
		return errors.New("wildcard '*' must appear only as trailing '/*' segment")
	}
	_, err := canonicalizeSPIFFEURI(pattern, true)
	return err
}

// matchSPIFFEID returns true if clientID is a canonical SPIFFE ID matching any pattern in patterns.
func matchSPIFFEID(clientID string, patterns []string) bool {
	canonClient, err := canonicalizeSPIFFEURI(clientID, true)
	if err != nil {
		return false
	}

	for _, pattern := range patterns {
		pattern = strings.TrimSpace(pattern)
		if pattern == "" {
			continue
		}
		if pattern == "*" {
			return true
		}
		if strings.HasSuffix(pattern, "/*") {
			base := strings.TrimSuffix(pattern, "/*")
			canonBase, err := canonicalizeSPIFFEURI(base, false)
			if err != nil {
				continue
			}
			if strings.HasPrefix(canonClient, canonBase+"/") {
				return true
			}
			continue
		}
		if strings.Contains(pattern, "*") {
			continue
		}
		canonPat, err := canonicalizeSPIFFEURI(pattern, true)
		if err != nil {
			continue
		}
		if canonClient == canonPat {
			return true
		}
	}
	return false
}
