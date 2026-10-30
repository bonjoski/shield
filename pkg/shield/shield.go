package shield

import (
	"errors"
	"fmt"
	"strings"
)

var (
	// ErrSecretLeakageDetected is returned by FailClosedWireGuard if unredacted secrets escape.
	ErrSecretLeakageDetected = errors.New("fail-closed wire guard: unredacted secret detected in outbound payload")
)

// Config configures the detection and redaction behavior of the Shield engine.
type Config struct {
	MinEntropyLen    int     // Minimum length of candidate token to check entropy (default: 16)
	EntropyThreshold float64 // Shannon entropy threshold (default: 4.2)
	Patterns         []SecretPattern
	CustomVaultKeys  map[string]string // Known credentials mapped by name (e.g. from Locksmith)
}

// DefaultConfig returns the production baseline configuration.
func DefaultConfig() Config {
	return Config{
		MinEntropyLen:    16,
		EntropyThreshold: 4.2,
		Patterns:         BuiltinPatterns,
		CustomVaultKeys:  make(map[string]string),
	}
}

// Engine performs client-side pre-flight secret tokenization and wire shielding.
type Engine struct {
	cfg Config
}

// NewEngine initializes a Shield engine with the provided configuration.
func NewEngine(cfg Config) *Engine {
	if cfg.MinEntropyLen == 0 {
		cfg.MinEntropyLen = 16
	}
	if cfg.EntropyThreshold == 0.0 {
		cfg.EntropyThreshold = 4.2
	}
	if len(cfg.Patterns) == 0 {
		cfg.Patterns = BuiltinPatterns
	}
	if cfg.CustomVaultKeys == nil {
		cfg.CustomVaultKeys = make(map[string]string)
	}
	return &Engine{cfg: cfg}
}

// normalizeInvisibleChars strips zero-width and invisible unicode characters
// used by adversaries attempting to evade regex matching and entropy checks.
func normalizeInvisibleChars(s string) string {
	s = strings.ReplaceAll(s, "\u200b", "") // Zero-width space
	s = strings.ReplaceAll(s, "\u200c", "") // Zero-width non-joiner
	s = strings.ReplaceAll(s, "\u200d", "") // Zero-width joiner
	s = strings.ReplaceAll(s, "\ufeff", "") // Zero-width no-break space (BOM)
	return s
}

// Redact scans the input string, substitutes all discovered secrets with opaque
// placeholders (e.g. "[SECRET_REF_e7a9b1c2]"), and stores mappings in a TokenMap.
func (e *Engine) Redact(input string) (string, *TokenMap, error) {
	tm := NewTokenMap()
	output := normalizeInvisibleChars(input)

	// 1. First Pass: Synchronized Vault Credentials (exact matches)
	for name, secret := range e.cfg.CustomVaultKeys {
		if len(secret) < 4 {
			continue
		}
		if strings.Contains(output, secret) {
			ref := tm.Add(secret, name)
			output = strings.ReplaceAll(output, secret, ref)
		}
	}

	// 2. Second Pass: High-Fidelity RegEx Patterns
	for _, p := range e.cfg.Patterns {
		matches := p.Regex.FindAllStringSubmatch(output, -1)
		for _, m := range matches {
			if len(m) == 0 {
				continue
			}
			// If pattern has a capturing group (like URI password or assignment value), use group 1
			candidate := m[0]
			if len(m) > 1 && len(m[1]) > 0 {
				candidate = m[1]
			}

			// Don't redact placeholders that were already created or strings containing them
			if strings.Contains(candidate, "[SECRET_REF_") {
				continue
			}

			// If the pattern defines an entropy check, verify entropy
			if p.Entropy > 0 && !IsHighEntropy(candidate, p.MinLen, p.Entropy) {
				continue
			}

			ref := tm.Add(candidate, p.Name)
			output = strings.ReplaceAll(output, candidate, ref)
		}
	}

	// 3. Third Pass: High-Entropy Word Scanning (for unformatted raw tokens)
	words := strings.Fields(output)
	for _, w := range words {
		// Clean trailing punctuation
		cleaned := strings.Trim(w, `"',;:()[]{}<>`)
		if strings.HasPrefix(cleaned, "[SECRET_REF_") && strings.HasSuffix(cleaned, "]") {
			continue
		}
		if IsHighEntropy(cleaned, e.cfg.MinEntropyLen, e.cfg.EntropyThreshold) {
			ref := tm.Add(cleaned, "High-Entropy Token")
			output = strings.ReplaceAll(output, cleaned, ref)
		}
	}

	return output, tm, nil
}

// Restore substitutes all placeholder tokens in text back to their original secret values.
// Handles nested placeholder substitutions iteratively until all placeholders are resolved.
func (e *Engine) Restore(text string, tm *TokenMap) string {
	if tm == nil {
		return text
	}

	result := text
	// Iteratively resolve up to 5 passes in case of nested placeholder expansions
	for pass := 0; pass < 5; pass++ {
		changed := false
		for _, ref := range tm.References() {
			if strings.Contains(result, ref) {
				if secret, ok := tm.GetSecret(ref); ok {
					result = strings.ReplaceAll(result, ref, secret)
					changed = true
				}
			}
		}
		if !changed || !strings.Contains(result, "[SECRET_REF_") {
			break
		}
	}
	return result
}

// FailClosedWireGuard performs a final safety check on the serialized payload before
// transmission over the network. If any unredacted pattern or high-entropy token is found,
// the outbound call aborts immediately.
func (e *Engine) FailClosedWireGuard(payload []byte) error {
	s := normalizeInvisibleChars(string(payload))

	// 1. Vault credentials check
	for name, secret := range e.cfg.CustomVaultKeys {
		if len(secret) >= 4 && strings.Contains(s, secret) {
			return fmt.Errorf("%w: matched custom vault key %s", ErrSecretLeakageDetected, name)
		}
	}

	// 2. High-fidelity patterns check
	for _, p := range e.cfg.Patterns {
		if len(p.Regex.SubexpNames()) > 1 {
			matches := p.Regex.FindAllStringSubmatch(s, -1)
			for _, m := range matches {
				if len(m) > 1 && len(m[1]) > 0 {
					if !strings.HasPrefix(m[1], "[SECRET_REF_") {
						return fmt.Errorf("%w: unshielded credential in %s", ErrSecretLeakageDetected, p.Name)
					}
				}
			}
		} else {
			if p.Regex.MatchString(s) {
				return fmt.Errorf("%w: matched %s", ErrSecretLeakageDetected, p.Name)
			}
		}
	}

	return nil
}
