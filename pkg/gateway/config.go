package gateway

import (
	"log"
	"net/http"
)

// Default settings for the Keyless AI Gateway Adapter.
const (
	DefaultListenAddr          = "127.0.0.1:8080"
	DefaultUpstreamURL         = "https://api.openai.com/v1"
	DefaultVaultSecret         = "openai/api-key"
	DefaultMaxRequestBodyBytes = 10 << 20 // 10 MiB
)

// Config configures the Keyless AI Gateway Adapter reverse proxy.
type Config struct {
	// ListenAddr is the TCP address to bind (must be loopback, e.g. "127.0.0.1:8080").
	ListenAddr string

	// SocketPath is the optional Unix domain socket path for local IPC.
	SocketPath string

	// UpstreamURL is the base URL of the upstream model provider (e.g. "https://api.openai.com/v1").
	UpstreamURL string

	// VaultSecret is the identifier of the secret stored in Locksmith (e.g. "openai/api-key").
	VaultSecret string

	// AuthToken is an optional client authentication token required for incoming requests.
	AuthToken string

	// LocksmithSocket is an optional custom path to the Locksmith daemon Unix domain socket.
	LocksmithSocket string

	// SecretRetriever overrides the secret retrieval mechanism (useful for testing or mocks).
	SecretRetriever SecretRetriever

	// Logger is the base logger to use.
	Logger *log.Logger

	// HTTPClient overrides the outbound HTTP client (useful for testing or custom transports).
	HTTPClient *http.Client

	// MaxRequestBodyBytes limits incoming request payload size (defaults to 10 MiB).
	MaxRequestBodyBytes int64
}

// DefaultConfig returns a Config populated with standard defaults.
func DefaultConfig() Config {
	return Config{
		ListenAddr:          DefaultListenAddr,
		UpstreamURL:         DefaultUpstreamURL,
		VaultSecret:         DefaultVaultSecret,
		MaxRequestBodyBytes: DefaultMaxRequestBodyBytes,
	}
}
