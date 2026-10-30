package adversarial

import (
	"errors"
	"strings"
	"testing"

	"github.com/bonjoski/shield/pkg/reassembly"
	"github.com/bonjoski/shield/pkg/shield"
)

// ADV-01: Zero-Width Space & Unicode Smuggling Bypass
// Adversary injects zero-width invisible characters (\u200b, \u200c, \u200d, \ufeff)
// to break naive regex patterns and entropy scanning.
func TestADV01_ZeroWidthUnicodeSmuggling(t *testing.T) {
	cfg := shield.DefaultConfig()
	engine := shield.NewEngine(cfg)

	// Injected AWS Key with zero-width space
	smuggledAWS := "AKIA\u200bIOSFODNN7EXAMPLE"
	// Injected Anthropic Key with zero-width non-joiner
	smuggledAnthropic := "sk-ant-\u200capi03-abcdefghijklmnopqrstuvwxyz1234567890_test"

	payload := "Config: " + smuggledAWS + " and " + smuggledAnthropic

	redacted, tm, err := engine.Redact(payload)
	if err != nil {
		t.Fatalf("redact failed: %v", err)
	}

	// Verify secrets were caught despite unicode smuggling
	if strings.Contains(redacted, "AKIA") {
		t.Errorf("ADV-01 FAILED: Smuggled AWS key bypassed redaction: %s", redacted)
	}
	if strings.Contains(redacted, "sk-ant-") {
		t.Errorf("ADV-01 FAILED: Smuggled Anthropic key bypassed redaction: %s", redacted)
	}

	// Verify WireGuard blocks unredacted smuggled payload
	if err := engine.FailClosedWireGuard([]byte(payload)); err == nil {
		t.Errorf("ADV-01 FAILED: FailClosedWireGuard allowed smuggled unredacted payload")
	}

	// Restored should yield clean token without leaks
	restored := engine.Restore(redacted, tm)
	if !strings.Contains(restored, "AKIAIOSFODNN7EXAMPLE") {
		t.Errorf("ADV-01 FAILED: Restored payload does not contain original clean secret")
	}
}

// ADV-02: High-Entropy Word Exfiltration Detection
// Adversary uses an unformatted, un-prefixed high-entropy secret (e.g. random base64/hex token).
func TestADV02_HighEntropyWordExfiltration(t *testing.T) {
	cfg := shield.DefaultConfig()
	engine := shield.NewEngine(cfg)

	// High entropy un-prefixed token
	highEntropySecret := "k9J2m!xQ8$vP4zL7*wR1tY6#bN3cV5mZ"
	payload := "Authorization token: " + highEntropySecret

	redacted, _, err := engine.Redact(payload)
	if err != nil {
		t.Fatalf("redact failed: %v", err)
	}

	if strings.Contains(redacted, highEntropySecret) {
		t.Errorf("ADV-02 FAILED: High-entropy raw token escaped redaction: %s", redacted)
	}
	if !strings.Contains(redacted, "[SECRET_REF_") {
		t.Errorf("ADV-02 FAILED: Expected placeholder in redacted output")
	}
}

// ADV-03: Hallucinated Placeholder Injection Attack
// Adversarial LLM attempts to trick local system by hallucinating unmapped [SECRET_REF_...] tokens.
func TestADV03_HallucinatedPlaceholderInjection(t *testing.T) {
	r := reassembly.NewReassembler()
	tm := shield.NewTokenMap()
	validRef := tm.Add("legit_secret", "PROD_KEY")

	// Upstream LLM response includes a fabricated secret reference
	adversarialResponse := "Use " + validRef + " and also fake [SECRET_REF_99999999deadbeef]"

	err := r.CheckUnmappedPlaceholders(adversarialResponse, tm)
	if err == nil {
		t.Fatalf("ADV-03 FAILED: Reassembler accepted hallucinated unmapped token reference")
	}
	if !errors.Is(err, reassembly.ErrUnmappedToken) {
		t.Errorf("ADV-03 FAILED: Unexpected error type: %v", err)
	}
}

// ADV-04: Fail-Closed Wire Guard Blocks Direct Egress
// Simulates an unredacted payload reaching the network layer.
func TestADV04_FailClosedWireGuardBlocksDirectEgress(t *testing.T) {
	cfg := shield.DefaultConfig()
	cfg.CustomVaultKeys["DB_PASSWORD"] = "ultra_secret_db_pass_1234"
	engine := shield.NewEngine(cfg)

	leakVectors := []string{
		"AWS leak: AKIAIOSFODNN7EXAMPLE",
		"Anthropic leak: sk-ant-api03-abcdefghijklmnopqrstuvwxyz1234567890_test",
		"Vault key leak: ultra_secret_db_pass_1234",
		"Private key:\n-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0...\n-----END RSA PRIVATE KEY-----",
	}

	for _, vector := range leakVectors {
		err := engine.FailClosedWireGuard([]byte(vector))
		if err == nil {
			t.Errorf("ADV-04 FAILED: FailClosedWireGuard permitted leak vector: %s", vector)
		}
	}
}

// ADV-05: In-Memory Cryptographic Zeroization
// Verifies that TokenMap.Zeroize clears all sensitive buffers from memory.
func TestADV05_InMemoryCryptographicZeroization(t *testing.T) {
	tm := shield.NewTokenMap()
	secret1 := "super_secret_token_1"
	secret2 := "super_secret_token_2"

	ref1 := tm.Add(secret1, "KEY_1")
	ref2 := tm.Add(secret2, "KEY_2")

	if tm.Count() != 2 {
		t.Fatalf("expected count 2, got %d", tm.Count())
	}

	tm.Zeroize()

	if tm.Count() != 0 {
		t.Fatalf("ADV-05 FAILED: TokenMap count is %d after Zeroize", tm.Count())
	}

	if _, ok := tm.GetSecret(ref1); ok {
		t.Errorf("ADV-05 FAILED: Secret 1 still retrievable after Zeroize")
	}
	if _, ok := tm.GetSecret(ref2); ok {
		t.Errorf("ADV-05 FAILED: Secret 2 still retrievable after Zeroize")
	}
}

// ADV-06: Adversarial Syntax Corruption Detection
// Verifies that malformed or syntax-corrupted generated code is rejected before local filesystem write.
func TestADV06_AdversarialSyntaxCorruption(t *testing.T) {
	r := reassembly.NewReassembler()

	corruptCode := `
package main
func main() {
	fmt.Println("Broken payload"
`

	err := r.ValidateSyntax("go", corruptCode)
	if err == nil {
		t.Fatalf("ADV-06 FAILED: Reassembler accepted syntactically corrupted Go code")
	}
	if !errors.Is(err, reassembly.ErrSyntaxValidation) {
		t.Errorf("ADV-06 FAILED: Expected ErrSyntaxValidation, got: %v", err)
	}
}
