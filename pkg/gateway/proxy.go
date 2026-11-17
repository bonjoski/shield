package gateway

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

var (
	// ErrNonLoopbackListenAddr indicates an attempt to bind to a non-loopback network interface.
	ErrNonLoopbackListenAddr = errors.New("security violation: gateway proxy must bind strictly to a loopback address (127.0.0.1, localhost, [::1])")
	// ErrSymlinkSocket indicates an attempt to create a socket file at a symlink location.
	ErrSymlinkSocket = errors.New("security violation: socket path is a symlink")
	// ErrAlreadyRunning indicates the proxy server is already running.
	ErrAlreadyRunning = errors.New("gateway proxy server is already running")
)

// Server implements the Locksmith + Shield Keyless AI Gateway Adapter reverse proxy.
type Server struct {
	cfg         Config
	listener    net.Listener
	httpServer  *http.Server
	upstreamURL *url.URL
	retriever   SecretRetriever
	logger      *RedactingLogger
	httpClient  *http.Client

	mu      sync.Mutex
	running bool
}

// ExpandPath expands leading ~ to user's home directory.
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

// isLoopback checks whether an address or host is a valid loopback interface.
func isLoopback(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	host = strings.TrimSpace(host)
	if host == "" || host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	if ip != nil && ip.IsLoopback() {
		return true
	}
	return false
}

// NewServer initializes a new Keyless AI Gateway Adapter reverse proxy.
func NewServer(cfg Config) (*Server, error) {
	if cfg.UpstreamURL == "" {
		cfg.UpstreamURL = DefaultUpstreamURL
	}
	if cfg.VaultSecret == "" {
		cfg.VaultSecret = DefaultVaultSecret
	}
	if cfg.MaxRequestBodyBytes <= 0 {
		cfg.MaxRequestBodyBytes = DefaultMaxRequestBodyBytes
	}

	u, err := url.Parse(cfg.UpstreamURL)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return nil, fmt.Errorf("invalid upstream URL %q: %w", cfg.UpstreamURL, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("invalid upstream URL scheme %q, must be http or https", u.Scheme)
	}

	// Loopback enforcement: if using TCP (no socket), bind address MUST be loopback
	if cfg.SocketPath == "" {
		if cfg.ListenAddr == "" {
			cfg.ListenAddr = DefaultListenAddr
		}
		if !isLoopback(cfg.ListenAddr) {
			return nil, fmt.Errorf("%w: %q", ErrNonLoopbackListenAddr, cfg.ListenAddr)
		}
	}

	retriever := cfg.SecretRetriever
	if retriever == nil {
		retriever = NewLocksmithRetriever(cfg.LocksmithSocket)
	}

	redactor := NewRedactingLogger(cfg.Logger)
	if cfg.AuthToken != "" {
		redactor.RegisterSecret(cfg.AuthToken)
	}

	httpClient := cfg.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{
			// Set transport-level timeouts without bounding total streaming completion time
			Transport: &http.Transport{
				DialContext: (&net.Dialer{
					Timeout:   10 * time.Second,
					KeepAlive: 30 * time.Second,
				}).DialContext,
				ResponseHeaderTimeout: 60 * time.Second,
				IdleConnTimeout:       90 * time.Second,
				TLSHandshakeTimeout:   10 * time.Second,
				MaxIdleConns:          100,
				MaxIdleConnsPerHost:   20,
			},
		}
	}

	s := &Server{
		cfg:         cfg,
		upstreamURL: u,
		retriever:   retriever,
		logger:      redactor,
		httpClient:  httpClient,
	}

	return s, nil
}

// Config returns a copy of the server configuration.
func (s *Server) Config() Config {
	return s.cfg
}

// ListenerAddr returns the actual listening address of the server.
func (s *Server) ListenerAddr() net.Addr {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.listener != nil {
		return s.listener.Addr()
	}
	return nil
}

// URL returns the base HTTP URL clients can connect to.
func (s *Server) URL() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.listener == nil {
		return ""
	}
	if s.cfg.SocketPath != "" {
		return "http://localhost"
	}
	return "http://" + s.listener.Addr().String()
}

func cleanupSocket(sockPath string) error {
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
		return ErrSymlinkSocket
	}
	return os.Remove(sockPath)
}

// Start launches the reverse proxy server on the configured listener.
func (s *Server) Start() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.running {
		return ErrAlreadyRunning
	}

	var l net.Listener
	var err error

	if s.cfg.SocketPath != "" {
		expanded := ExpandPath(s.cfg.SocketPath)

		// Check for symlink hijacking
		if fi, lerr := os.Lstat(expanded); lerr == nil {
			if fi.Mode()&os.ModeSymlink != 0 {
				return ErrSymlinkSocket
			}
			if err := os.Remove(expanded); err != nil && !errors.Is(err, os.ErrNotExist) {
				return fmt.Errorf("failed to remove existing socket %s: %w", expanded, err)
			}
		}

		dir := filepath.Dir(expanded)
		if err := os.MkdirAll(dir, 0700); err != nil {
			return fmt.Errorf("failed to create socket directory %s: %w", dir, err)
		}

		l, err = net.Listen("unix", expanded)
		if err != nil {
			return fmt.Errorf("failed to listen on unix socket %s: %w", expanded, err)
		}

		if err := os.Chmod(expanded, 0600); err != nil {
			_ = l.Close()
			_ = cleanupSocket(expanded)
			return fmt.Errorf("failed to set socket permissions on %s: %w", expanded, err)
		}
	} else {
		l, err = net.Listen("tcp", s.cfg.ListenAddr)
		if err != nil {
			return fmt.Errorf("failed to listen on tcp address %s: %w", s.cfg.ListenAddr, err)
		}
	}

	s.listener = l
	s.httpServer = &http.Server{
		Handler:           s,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    1 << 20, // 1 MiB
	}
	s.running = true

	go func() {
		_ = s.httpServer.Serve(l)
	}()

	return nil
}

// Stop gracefully stops the server and cleans up socket resources.
func (s *Server) Stop(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.running || s.httpServer == nil {
		return nil
	}

	s.running = false
	err := s.httpServer.Shutdown(ctx)

	if s.cfg.SocketPath != "" {
		if rmErr := cleanupSocket(ExpandPath(s.cfg.SocketPath)); rmErr != nil && err == nil {
			err = rmErr
		}
	}

	return err
}

func (s *Server) writeJSONError(w http.ResponseWriter, status int, msg, errType string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"error": map[string]any{
			"message": msg,
			"type":    errType,
			"code":    status,
		},
	})
}

func extractClientToken(r *http.Request) string {
	auth := r.Header.Get("Authorization")
	if auth != "" {
		parts := strings.SplitN(auth, " ", 2)
		if len(parts) == 2 && strings.EqualFold(parts[0], "Bearer") {
			return strings.TrimSpace(parts[1])
		}
		return strings.TrimSpace(auth)
	}

	if key := r.Header.Get("x-api-key"); key != "" {
		return strings.TrimSpace(key)
	}

	if key := r.Header.Get("api-key"); key != "" {
		return strings.TrimSpace(key)
	}

	return ""
}

func (s *Server) authenticateClient(r *http.Request) bool {
	if s.cfg.AuthToken == "" {
		return true
	}
	clientToken := extractClientToken(r)
	if clientToken == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(clientToken), []byte(s.cfg.AuthToken)) == 1
}

// resolveUpstreamURL computes the target URL, stripping duplicate /v1 paths if needed.
func resolveUpstreamURL(base *url.URL, incoming *url.URL) (*url.URL, error) {
	target := *base
	basePath := strings.TrimRight(base.Path, "/")
	incPath := incoming.Path

	if strings.HasPrefix(incPath, "/v1/") && strings.HasSuffix(basePath, "/v1") {
		target.Path = basePath + strings.TrimPrefix(incPath, "/v1")
	} else if incPath == "/v1" && strings.HasSuffix(basePath, "/v1") {
		target.Path = basePath
	} else if basePath != "" && !strings.HasPrefix(incPath, "/") {
		target.Path = basePath + "/" + incPath
	} else {
		target.Path = basePath + incPath
	}

	target.RawQuery = incoming.RawQuery
	return &target, nil
}

// ServeHTTP handles incoming requests, validates client auth, injects on-demand credentials,
// and proxies streaming completions to the upstream model provider.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// 1. Health probe bypass
	if r.URL.Path == "/health" || r.URL.Path == "/healthz" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok","gateway":"shield-keyless"}`))
		return
	}

	// 2. Client Authentication Validation
	if !s.authenticateClient(r) {
		s.writeJSONError(w, http.StatusUnauthorized, "Unauthorized: invalid or missing authentication token", "auth_error")
		return
	}

	// 3. Bound request body to prevent memory exhaustion
	if s.cfg.MaxRequestBodyBytes > 0 {
		r.Body = http.MaxBytesReader(w, r.Body, s.cfg.MaxRequestBodyBytes)
	}

	// 4. On-demand Upstream Secret Retrieval from Locksmith
	secret, err := s.retriever.GetSecret(r.Context(), s.cfg.VaultSecret)
	if err != nil {
		s.logger.Printf("[gateway] Failed to retrieve secret for vault key %q: %v", s.cfg.VaultSecret, err)
		s.writeJSONError(w, http.StatusBadGateway, "Keyless gateway failed to retrieve upstream secret", "gateway_error")
		return
	}

	// Guarantee that the secret buffer is zeroized from RAM immediately upon request exit / connection close
	defer secret.Zeroize()

	// Register secret in logger's redaction table to guarantee zero leakage in debug logs
	s.logger.RegisterSecret(secret.String())

	// 5. Resolve target upstream URL
	targetURL, err := resolveUpstreamURL(s.upstreamURL, r.URL)
	if err != nil {
		s.writeJSONError(w, http.StatusBadRequest, "Invalid request URL", "invalid_request_error")
		return
	}

	// 6. Build outbound request
	outReq, err := http.NewRequestWithContext(r.Context(), r.Method, targetURL.String(), r.Body)
	if err != nil {
		s.writeJSONError(w, http.StatusInternalServerError, "Failed to create upstream request", "gateway_error")
		return
	}

	// Copy allowed client headers (filtering out authentication headers and Host)
	for key, values := range r.Header {
		lowerKey := strings.ToLower(key)
		if lowerKey == "authorization" || lowerKey == "x-api-key" || lowerKey == "api-key" ||
			lowerKey == "proxy-authorization" || lowerKey == "host" {
			continue
		}
		for _, v := range values {
			outReq.Header.Add(key, v)
		}
	}

	outReq.Host = s.upstreamURL.Host

	// 7. Inject provider Authorization header into outbound request
	secretVal := secret.String()
	outReq.Header.Set("Authorization", "Bearer "+secretVal)

	// If upstream is Anthropic, also set x-api-key header
	if strings.Contains(s.upstreamURL.Host, "anthropic.com") || r.Header.Get("anthropic-version") != "" {
		outReq.Header.Set("x-api-key", secretVal)
	}

	s.logger.Printf("[gateway] Proxying %s %s -> %s", r.Method, r.URL.Path, targetURL.String())

	// 8. Execute outbound request to upstream model provider
	resp, err := s.httpClient.Do(outReq)
	if err != nil {
		var maxBytesErr *http.MaxBytesError
		if errors.As(err, &maxBytesErr) {
			s.writeJSONError(w, http.StatusRequestEntityTooLarge, "Request payload exceeds size limit", "invalid_request_error")
			return
		}
		s.logger.Printf("[gateway] Upstream request failed: %v", err)
		s.writeJSONError(w, http.StatusBadGateway, "Upstream model provider request failed", "upstream_error")
		return
	}
	defer resp.Body.Close()

	// 9. Relay response headers and status code
	for key, values := range resp.Header {
		for _, v := range values {
			w.Header().Add(key, v)
		}
	}
	w.Header().Set("X-Shield-Gateway", "keyless-enclave-active")
	w.WriteHeader(resp.StatusCode)

	// 10. Transparently stream response chunks back to the client
	flusher, isFlusher := w.(http.Flusher)
	buf := make([]byte, 32*1024)
	for {
		n, rErr := resp.Body.Read(buf)
		if n > 0 {
			if _, wErr := w.Write(buf[:n]); wErr != nil {
				break
			}
			if isFlusher {
				flusher.Flush()
			}
		}
		if rErr != nil {
			break
		}
	}
}
