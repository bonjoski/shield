package gateway

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
	"unsafe"
)

// ExplicitBzero overwrites the given byte slice with zeroes in a manner that
// prevents compiler dead-store elimination (DSE).
//
//go:noinline
func ExplicitBzero(b []byte) {
	if len(b) == 0 {
		return
	}
	ptr := (*byte)(unsafe.Pointer(&b[0]))
	for i := 0; i < len(b); i++ {
		*(*byte)(unsafe.Pointer(uintptr(unsafe.Pointer(ptr)) + uintptr(i))) = 0
	}
	runtime.KeepAlive(ptr)
	runtime.KeepAlive(b)
}

// Secret wraps an in-memory secret byte buffer that can be actively zeroized.
type Secret struct {
	mu   sync.Mutex
	data []byte
}

// NewSecret wraps the provided bytes into a new Secret.
// Note: It makes an owned copy of the data.
func NewSecret(data []byte) *Secret {
	if data == nil {
		return &Secret{data: nil}
	}
	cp := make([]byte, len(data))
	copy(cp, data)
	return &Secret{data: cp}
}

// Bytes returns the raw secret bytes.
func (s *Secret) Bytes() []byte {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.data
}

// String returns the secret as a string.
func (s *Secret) String() string {
	if s == nil {
		return ""
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return string(s.data)
}

// Zeroize securely wipes the underlying secret buffer with zeros.
func (s *Secret) Zeroize() {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.data != nil {
		ExplicitBzero(s.data)
		s.data = nil
	}
}

// IsZeroized reports whether the secret buffer has been zeroized or is empty.
func (s *Secret) IsZeroized() bool {
	if s == nil {
		return true
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.data) == 0 {
		return true
	}
	for _, b := range s.data {
		if b != 0 {
			return false
		}
	}
	return true
}

// SecretRetriever defines the interface for fetching upstream API keys on demand.
type SecretRetriever interface {
	GetSecret(ctx context.Context, secretName string) (*Secret, error)
}

// LocksmithRetriever retrieves secrets on-demand from the Locksmith hardware daemon
// over a local Unix domain socket, with automatic fallback to environment variables.
type LocksmithRetriever struct {
	socketPath string
}

// NewLocksmithRetriever initializes a retriever with an optional custom socket path.
func NewLocksmithRetriever(socketPath string) *LocksmithRetriever {
	return &LocksmithRetriever{
		socketPath: socketPath,
	}
}

// CandidateLocksmithSockets returns ordered candidate socket paths for Locksmith.
func (r *LocksmithRetriever) CandidateSockets() []string {
	var candidates []string
	if r.socketPath != "" {
		candidates = append(candidates, r.socketPath)
	}
	if envSock := os.Getenv("LOCKSMITH_SOCKET"); envSock != "" {
		candidates = append(candidates, envSock)
	}

	home, err := os.UserHomeDir()
	if err == nil && home != "" {
		candidates = append(candidates,
			filepath.Join(home, ".locksmith", "locksmithd.sock"),
			filepath.Join(home, ".locksmith", "locksmith.sock"),
		)
	}

	candidates = append(candidates,
		"/var/run/locksmith/vault.sock",
		filepath.Join(os.TempDir(), fmt.Sprintf("locksmithd-%d.sock", os.Getuid())),
	)

	return candidates
}

type etxLeaseRequest struct {
	Version    string `json:"version"`
	Action     string `json:"action"`
	ClientPID  int    `json:"client_pid"`
	SecretName string `json:"secret_name"`
	LeaseTTL   int64  `json:"lease_ttl"`
	MaxUses    int    `json:"max_uses"`
	SpiffeID   string `json:"spiffe_id,omitempty"`
}

type etxLeaseResponse struct {
	Status      string          `json:"status"`
	LeaseID     string          `json:"lease_id,omitempty"`
	SecretValue json.RawMessage `json:"secret_value,omitempty"`
	Error       string          `json:"error,omitempty"`
}

func (r *LocksmithRetriever) queryLocksmithSocket(ctx context.Context, sockPath, secretName string) ([]byte, error) {
	if _, err := os.Stat(sockPath); err != nil {
		return nil, err
	}

	var d net.Dialer
	conn, err := d.DialContext(ctx, "unix", sockPath)
	if err != nil {
		return nil, fmt.Errorf("failed to dial locksmith socket %s: %w", sockPath, err)
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	req := etxLeaseRequest{
		Version:    "1.0",
		Action:     "request_lease",
		ClientPID:  os.Getpid(),
		SecretName: secretName,
		LeaseTTL:   int64(30 * time.Second),
		MaxUses:    1,
		SpiffeID:   "spiffe://bonjoski.local/shield/gateway",
	}

	reqBytes, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal lease request: %w", err)
	}

	if _, err := conn.Write(reqBytes); err != nil {
		return nil, fmt.Errorf("failed to write lease request to socket: %w", err)
	}

	respBuf := make([]byte, 65536)
	n, err := conn.Read(respBuf)
	if err != nil {
		return nil, fmt.Errorf("failed to read lease response: %w", err)
	}

	var resp etxLeaseResponse
	if err := json.Unmarshal(respBuf[:n], &resp); err != nil {
		return nil, fmt.Errorf("failed to parse lease response: %w", err)
	}

	if resp.Status != "GRANTED" {
		return nil, fmt.Errorf("locksmith lease denied for %q: status=%s, error=%s", secretName, resp.Status, resp.Error)
	}

	if len(resp.SecretValue) == 0 {
		return nil, fmt.Errorf("locksmith granted lease but returned empty secret for %q", secretName)
	}

	// Unmarshal secret_value: Go's json.Unmarshal on []byte handles base64 automatically.
	var rawBytes []byte
	if err := json.Unmarshal(resp.SecretValue, &rawBytes); err == nil && len(rawBytes) > 0 {
		return rawBytes, nil
	}

	// Fallback if returned as raw string
	var strVal string
	if err := json.Unmarshal(resp.SecretValue, &strVal); err == nil && strVal != "" {
		return []byte(strVal), nil
	}

	return resp.SecretValue, nil
}

// NormalizeEnvName converts a secret name like "openai/api-key" into "OPENAI_API_KEY".
func NormalizeEnvName(secretName string) string {
	s := strings.ToUpper(secretName)
	s = strings.ReplaceAll(s, "/", "_")
	s = strings.ReplaceAll(s, "-", "_")
	s = strings.ReplaceAll(s, ".", "_")
	return s
}

// FallbackFromEnvironment searches candidate environment variables for the secret name.
func FallbackFromEnvironment(secretName string) ([]byte, bool) {
	candidates := []string{
		secretName,
		NormalizeEnvName(secretName),
	}

	lower := strings.ToLower(secretName)
	if strings.Contains(lower, "openai") {
		candidates = append(candidates, "OPENAI_API_KEY")
	}
	if strings.Contains(lower, "anthropic") || strings.Contains(lower, "claude") {
		candidates = append(candidates, "ANTHROPIC_API_KEY")
	}
	if strings.Contains(lower, "gemini") {
		candidates = append(candidates, "GEMINI_API_KEY")
	}
	if strings.Contains(lower, "groq") {
		candidates = append(candidates, "GROQ_API_KEY")
	}

	for _, cand := range candidates {
		if val, ok := os.LookupEnv(cand); ok && strings.TrimSpace(val) != "" {
			return []byte(val), true
		}
	}
	return nil, false
}

// GetSecret attempts Locksmith UDS socket retrieval first, falling back to environment variables.
func (r *LocksmithRetriever) GetSecret(ctx context.Context, secretName string) (*Secret, error) {
	for _, sockPath := range r.CandidateSockets() {
		raw, err := r.queryLocksmithSocket(ctx, sockPath, secretName)
		if err == nil && len(raw) > 0 {
			sec := NewSecret(raw)
			ExplicitBzero(raw)
			return sec, nil
		}
	}

	// Fallback to environment
	if val, ok := FallbackFromEnvironment(secretName); ok {
		sec := NewSecret(val)
		return sec, nil
	}

	return nil, fmt.Errorf("secret %q not found in Locksmith UDS daemon or environment", secretName)
}

// MockSecretRetriever implements SecretRetriever for unit and integration tests.
type MockSecretRetriever struct {
	mu      sync.RWMutex
	secrets map[string][]byte
	lastSec *Secret
}

// NewMockSecretRetriever creates a mock retriever preloaded with secrets.
func NewMockSecretRetriever(secrets map[string][]byte) *MockSecretRetriever {
	store := make(map[string][]byte)
	for k, v := range secrets {
		cp := make([]byte, len(v))
		copy(cp, v)
		store[k] = cp
	}
	return &MockSecretRetriever{
		secrets: store,
	}
}

// SetSecret updates or inserts a mock secret.
func (m *MockSecretRetriever) SetSecret(name string, value []byte) {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := make([]byte, len(value))
	copy(cp, value)
	m.secrets[name] = cp
}

// LastReturnedSecret returns the most recently returned Secret instance (for testing zeroization).
func (m *MockSecretRetriever) LastReturnedSecret() *Secret {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.lastSec
}

// GetSecret fetches secret from the mock store.
func (m *MockSecretRetriever) GetSecret(_ context.Context, secretName string) (*Secret, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	val, ok := m.secrets[secretName]
	if !ok {
		return nil, fmt.Errorf("mock secret not found: %s", secretName)
	}

	sec := NewSecret(val)
	m.lastSec = sec
	return sec, nil
}
