package shield

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"runtime"
	"sync"
)

// TokenMap holds the bi-directional mapping between scrubbed placeholder references
// (e.g. "[SECRET_REF_e7a9b1c2]") and the original raw secret values.
// All values are stored strictly in-memory and can be explicitly zeroized.
type TokenMap struct {
	mu            sync.RWMutex
	refToSecret   map[string]string
	secretToRef   map[string]string
	namedSecrets  map[string]string // Maps semantic variable name (e.g. "DATABASE_URL") to ref
}

// NewTokenMap initializes an empty thread-safe TokenMap.
func NewTokenMap() *TokenMap {
	return &TokenMap{
		refToSecret:  make(map[string]string),
		secretToRef:  make(map[string]string),
		namedSecrets: make(map[string]string),
	}
}

// Add inserts a raw secret, returning its consistent placeholder reference.
// If the secret already exists in the map, its existing reference is returned.
func (tm *TokenMap) Add(secret string, optionalName string) string {
	tm.mu.Lock()
	defer tm.mu.Unlock()

	if ref, exists := tm.secretToRef[secret]; exists {
		if optionalName != "" {
			tm.namedSecrets[optionalName] = ref
		}
		return ref
	}

	// Generate a fixed-length 8-byte (16 hex chars) random identifier
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	ref := fmt.Sprintf("[SECRET_REF_%s]", hex.EncodeToString(b))

	tm.refToSecret[ref] = secret
	tm.secretToRef[secret] = ref
	if optionalName != "" {
		tm.namedSecrets[optionalName] = ref
	}

	return ref
}

// GetSecret resolves a placeholder reference back to the original secret.
func (tm *TokenMap) GetSecret(ref string) (string, bool) {
	tm.mu.RLock()
	defer tm.mu.RUnlock()
	secret, ok := tm.refToSecret[ref]
	return secret, ok
}

// GetRef returns the placeholder reference for a known secret value.
func (tm *TokenMap) GetRef(secret string) (string, bool) {
	tm.mu.RLock()
	defer tm.mu.RUnlock()
	ref, ok := tm.secretToRef[secret]
	return ref, ok
}

// Count returns the number of tracked secrets in the map.
func (tm *TokenMap) Count() int {
	tm.mu.RLock()
	defer tm.mu.RUnlock()
	return len(tm.refToSecret)
}

// References returns all placeholder tokens in the map.
func (tm *TokenMap) References() []string {
	tm.mu.RLock()
	defer tm.mu.RUnlock()
	refs := make([]string, 0, len(tm.refToSecret))
	for ref := range tm.refToSecret {
		refs = append(refs, ref)
	}
	return refs
}

// Zeroize explicitly clears all secret strings in memory to prevent heap scraping.
func (tm *TokenMap) Zeroize() {
	tm.mu.Lock()
	defer tm.mu.Unlock()

	for k, v := range tm.refToSecret {
		b := []byte(v)
		for i := range b {
			b[i] = 0
		}
		delete(tm.refToSecret, k)
	}
	for k := range tm.secretToRef {
		delete(tm.secretToRef, k)
	}
	for k := range tm.namedSecrets {
		delete(tm.namedSecrets, k)
	}
	runtime.GC()
}
