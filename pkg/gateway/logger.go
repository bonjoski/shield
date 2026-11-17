package gateway

import (
	"fmt"
	"io"
	"log"
	"regexp"
	"strings"
	"sync"
)

var (
	// bearerRegex matches Bearer token patterns in headers or log lines.
	bearerRegex = regexp.MustCompile(`(?i)(bearer\s+)([A-Za-z0-9_\-\.]{8,})`)
	// apiKeyHeaderRegex matches x-api-key patterns.
	apiKeyHeaderRegex = regexp.MustCompile(`(?i)(x-api-key\s*[:=]\s*)([A-Za-z0-9_\-\.]{8,})`)
	// standardKeyRegex matches typical API key formats (sk-..., ghp_..., etc.).
	standardKeyRegex = regexp.MustCompile(`(?i)(sk-[a-zA-Z0-9_\-]{16,}|ghp_[a-zA-Z0-9]{20,}|key-[a-zA-Z0-9]{16,})`)
)

// RedactingLogger wraps a standard logger to ensure that secrets and auth tokens
// are stripped from all log messages.
type RedactingLogger struct {
	mu      sync.RWMutex
	out     *log.Logger
	secrets []string
}

// NewRedactingLogger initializes a RedactingLogger.
func NewRedactingLogger(out *log.Logger, secrets ...string) *RedactingLogger {
	if out == nil {
		out = log.New(io.Discard, "[gateway] ", log.LstdFlags)
	}
	rl := &RedactingLogger{
		out: out,
	}
	for _, s := range secrets {
		rl.RegisterSecret(s)
	}
	return rl
}

// RegisterSecret adds a secret string to the redaction dictionary.
func (rl *RedactingLogger) RegisterSecret(s string) {
	s = strings.TrimSpace(s)
	if len(s) < 4 {
		return
	}
	rl.mu.Lock()
	defer rl.mu.Unlock()
	for _, existing := range rl.secrets {
		if existing == s {
			return
		}
	}
	rl.secrets = append(rl.secrets, s)
}

// Sanitize strips all registered secrets and detected token formats from the message.
func (rl *RedactingLogger) Sanitize(msg string) string {
	rl.mu.RLock()
	secretsCopy := append([]string(nil), rl.secrets...)
	rl.mu.RUnlock()

	for _, sec := range secretsCopy {
		if sec != "" {
			msg = strings.ReplaceAll(msg, sec, "[REDACTED]")
		}
	}

	msg = bearerRegex.ReplaceAllString(msg, "${1}[REDACTED]")
	msg = apiKeyHeaderRegex.ReplaceAllString(msg, "${1}[REDACTED]")
	msg = standardKeyRegex.ReplaceAllString(msg, "[REDACTED_API_KEY]")

	return msg
}

// Printf logs a sanitized formatted message.
func (rl *RedactingLogger) Printf(format string, args ...any) {
	if rl == nil || rl.out == nil {
		return
	}
	raw := fmt.Sprintf(format, args...)
	sanitized := rl.Sanitize(raw)
	rl.out.Print(sanitized)
}
