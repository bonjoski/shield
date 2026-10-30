package shield

import (
	"math"
)

// ShannonEntropy calculates the Shannon entropy of a string in bits per character.
// Strings with high randomness (like cryptographic keys and tokens) typically score > 4.2.
func ShannonEntropy(s string) float64 {
	if len(s) == 0 {
		return 0.0
	}

	freq := make(map[rune]float64)
	for _, c := range s {
		freq[c]++
	}

	length := float64(len([]rune(s)))
	var entropy float64
	for _, count := range freq {
		p := count / length
		entropy -= p * math.Log2(p)
	}

	return entropy
}

// IsHighEntropy returns true if the candidate token exceeds the minimum entropy threshold
// and has sufficient length to qualify as a suspected cryptographic credential.
func IsHighEntropy(s string, minLen int, threshold float64) bool {
	if len(s) < minLen {
		return false
	}
	return ShannonEntropy(s) >= threshold
}
