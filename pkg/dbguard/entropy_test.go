package dbguard

import (
	"crypto/rand"
	"encoding/base64"
	"testing"

	"github.com/jackc/pgproto3/v2"
)

func TestCalculateShannonEntropy(t *testing.T) {
	// Empty data
	if ent := CalculateShannonEntropy(nil); ent != 0.0 {
		t.Fatalf("Expected 0.0 for nil data, got %f", ent)
	}

	// Repeated single character (0 entropy)
	allA := []byte("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
	if ent := CalculateShannonEntropy(allA); ent != 0.0 {
		t.Fatalf("Expected 0.0 for uniform repeated bytes, got %f", ent)
	}

	// Normal English text (typically 3.0 - 4.2)
	english := []byte("The quick brown fox jumps over the lazy dog. Crucible is a database capability shim.")
	engEntropy := CalculateShannonEntropy(english)
	if engEntropy < 3.0 || engEntropy > 4.5 {
		t.Fatalf("Expected English entropy between 3.0 and 4.5, got %f", engEntropy)
	}

	// Random 256 bytes (close to 8.0)
	randomBytes := make([]byte, 512)
	_, _ = rand.Read(randomBytes)
	randEntropy := CalculateShannonEntropy(randomBytes)
	if randEntropy < 7.0 {
		t.Fatalf("Expected random byte entropy >= 7.0, got %f", randEntropy)
	}

	// Base64 secret key
	secretRaw := make([]byte, 64)
	_, _ = rand.Read(secretRaw)
	b64Key := []byte(base64.StdEncoding.EncodeToString(secretRaw))
	b64Entropy := CalculateShannonEntropy(b64Key)
	if b64Entropy < 5.0 {
		t.Fatalf("Expected base64 random secret entropy >= 5.0, got %f", b64Entropy)
	}
}

func TestScanner(t *testing.T) {
	scanner := NewScanner(5.0)

	// Short string below min length should not trigger
	ent, exceeds := scanner.Scan([]byte("secret"))
	if exceeds || ent != 0.0 {
		t.Fatalf("Expected short string not to exceed threshold")
	}

	// Plain English text should not exceed threshold of 5.0
	normalText := []byte("Customer John Doe, address 123 Main Street, New York, NY 10001, email john@example.com")
	ent, exceeds = scanner.Scan(normalText)
	if exceeds {
		t.Fatalf("Normal customer text incorrectly flagged as high entropy: %f", ent)
	}

	// High entropy encrypted blob should trigger
	cipherBlob := make([]byte, 128)
	_, _ = rand.Read(cipherBlob)
	ent, exceeds = scanner.Scan(cipherBlob)
	if !exceeds {
		t.Fatalf("Random encrypted blob failed to exceed threshold: %f", ent)
	}
}

func TestScanRow(t *testing.T) {
	scanner := NewScanner(5.0)

	// Normal row
	normalRow := &pgproto3.DataRow{
		Values: [][]byte{
			[]byte("1"),
			[]byte("Alice"),
			[]byte("alice@example.com"),
			[]byte("active"),
		},
	}
	_, exceeded := scanner.ScanRow(normalRow)
	if exceeded {
		t.Fatalf("Expected normal row not to exceed threshold")
	}

	// Row with leaked high-entropy master key
	secretKey := make([]byte, 64)
	_, _ = rand.Read(secretKey)
	leakRow := &pgproto3.DataRow{
		Values: [][]byte{
			[]byte("1"),
			[]byte("Alice"),
			secretKey,
		},
	}
	_, exceeded = scanner.ScanRow(leakRow)
	if !exceeded {
		t.Fatalf("Expected leak row with high-entropy key to exceed threshold")
	}
}
