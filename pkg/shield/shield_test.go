package shield

import (
	"strings"
	"testing"
)

func TestEntropyCalculation(t *testing.T) {
	// Low entropy strings
	low := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	if ShannonEntropy(low) != 0.0 {
		t.Fatalf("expected 0 entropy for uniform string, got %f", ShannonEntropy(low))
	}

	// Normal English text ~ 3.5 - 4.5 bits/char
	english := "This is a normal sentence with typical english words and frequent letters."
	entEng := ShannonEntropy(english)
	if entEng < 2.0 || entEng > 4.2 {
		t.Fatalf("expected english text entropy around 3.5, got %f", entEng)
	}

	// High entropy cryptographic key (base64 random ~ 5.0 - 5.8 bits/char)
	high := "k9J2m!xQ8$vP4zL7*wR1tY6#bN3cV5mZ"
	entHigh := ShannonEntropy(high)
	if entHigh < 4.5 {
		t.Fatalf("expected high entropy for base64 key, got %f", entHigh)
	}
}

func TestShieldRedactionAndRestore(t *testing.T) {
	cfg := DefaultConfig()
	cfg.CustomVaultKeys["MY_DB_PASS"] = "SuperSecretPassword999!"
	engine := NewEngine(cfg)

	rawInput := `
// Database configuration
const dbUrl = "postgres://admin:SuperSecretPassword999!@db.prod.internal:5432/main";
const awsKey = "AKIAIOSFODNN7EXAMPLE";
const anthropicKey = "sk-ant-api03-abcdefghijklmnopqrstuvwxyz1234567890_test";
const normalText = "Please refactor this code to use connection pooling.";
`

	redacted, tm, err := engine.Redact(rawInput)
	if err != nil {
		t.Fatalf("redact failed: %v", err)
	}
	t.Logf("Redacted text:\n%s", redacted)
	for _, ref := range tm.References() {
		sec, _ := tm.GetSecret(ref)
		t.Logf("Mapping: %s -> %s", ref, sec)
	}

	// Verify secrets were removed from redacted text
	if strings.Contains(redacted, "SuperSecretPassword999!") {
		t.Errorf("vault secret was not redacted")
	}
	if strings.Contains(redacted, "AKIAIOSFODNN7EXAMPLE") {
		t.Errorf("AWS key was not redacted")
	}
	if strings.Contains(redacted, "sk-ant-api03") {
		t.Errorf("Anthropic key was not redacted")
	}

	// Verify placeholders were created
	if !strings.Contains(redacted, "[SECRET_REF_") {
		t.Errorf("expected placeholder token in redacted text, got:\n%s", redacted)
	}

	// Verify WireGuard blocks unredacted payloads
	unredactedBytes := []byte("Here is my key: AKIAIOSFODNN7EXAMPLE")
	if err := engine.FailClosedWireGuard(unredactedBytes); err == nil {
		t.Errorf("expected FailClosedWireGuard to block unredacted AWS key")
	}

	// Verify WireGuard allows redacted payloads
	if err := engine.FailClosedWireGuard([]byte(redacted)); err != nil {
		t.Errorf("expected FailClosedWireGuard to pass on redacted payload, got: %v", err)
	}

	// Verify Restoration
	restored := engine.Restore(redacted, tm)
	if !strings.Contains(restored, "SuperSecretPassword999!") {
		t.Errorf("restored text does not contain original vault secret")
	}
	if !strings.Contains(restored, "AKIAIOSFODNN7EXAMPLE") {
		t.Errorf("restored text does not contain original AWS key")
	}
}

func TestTokenMapZeroization(t *testing.T) {
	tm := NewTokenMap()
	ref := tm.Add("Secret123456", "test")
	if count := tm.Count(); count != 1 {
		t.Fatalf("expected count 1, got %d", count)
	}

	tm.Zeroize()
	if count := tm.Count(); count != 0 {
		t.Fatalf("expected count 0 after zeroize, got %d", count)
	}
	if _, ok := tm.GetSecret(ref); ok {
		t.Fatalf("expected secret to be purged from map")
	}
}
