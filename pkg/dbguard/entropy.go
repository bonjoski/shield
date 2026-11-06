package dbguard

import (
	"math"

	"github.com/jackc/pgproto3/v2"
)

// DefaultThreshold is the default Shannon entropy threshold (bits/byte) above which data is considered high-entropy
// (e.g. AES ciphertext, random API keys, base64 blobs). Plain text English is ~2.5-4.0; uniform random 8-bit is ~7.5-8.0.
const DefaultThreshold = 5.0

// DefaultMinLength is the minimum byte length to evaluate entropy to avoid false positives on short strings.
const DefaultMinLength = 16

// CalculateShannonEntropy calculates Shannon entropy in bits per byte (0.0 to 8.0) for a byte slice.
func CalculateShannonEntropy(data []byte) float64 {
	if len(data) == 0 {
		return 0.0
	}

	var freq [256]int
	for _, b := range data {
		freq[b]++
	}

	length := float64(len(data))
	var entropy float64
	for _, count := range freq {
		if count > 0 {
			p := float64(count) / length
			entropy -= p * math.Log2(p)
		}
	}

	return entropy
}

// Scanner evaluates result sets and data rows for high Shannon 
type Scanner struct {
	Threshold float64
	MinLength int
}

// NewScanner creates a new Scanner with given threshold and default minimum length.
func NewScanner(threshold float64) *Scanner {
	if threshold <= 0 {
		threshold = DefaultThreshold
	}
	return &Scanner{
		Threshold: threshold,
		MinLength: DefaultMinLength,
	}
}

// Scan evaluates a byte slice. Returns the calculated entropy and whether it exceeds the threshold.
func (s *Scanner) Scan(data []byte) (float64, bool) {
	if len(data) < s.MinLength {
		return 0.0, false
	}
	ent := CalculateShannonEntropy(data)
	return ent, ent >= s.Threshold
}

// ScanRow inspects all column values in a DataRow for high-entropy contents.
// Returns the maximum entropy found across columns and whether any column exceeded the threshold.
func (s *Scanner) ScanRow(row *pgproto3.DataRow) (float64, bool) {
	if row == nil {
		return 0.0, false
	}

	var maxEntropy float64
	var exceeded bool

	for _, colVal := range row.Values {
		if colVal == nil || len(colVal) < s.MinLength {
			continue
		}
		ent := CalculateShannonEntropy(colVal)
		if ent > maxEntropy {
			maxEntropy = ent
		}
		if ent >= s.Threshold {
			exceeded = true
		}
	}

	return maxEntropy, exceeded
}
