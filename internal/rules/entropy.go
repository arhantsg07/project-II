package rules

import (
	"math"
	"strings"
)

// LeftmostLabelEntropy calculates Shannon entropy for the leftmost DNS label.
// Using the whole domain would score common multi-label hostnames too highly.
func LeftmostLabelEntropy(domain string) float64 {
	if domain == "" {
		return 0
	}
	label := strings.SplitN(domain, ".", 2)[0]
	if label == "" {
		return 0
	}

	counts := make(map[rune]int)
	for _, char := range label {
		counts[char]++
	}
	length := float64(len([]rune(label)))
	var entropy float64
	for _, count := range counts {
		probability := float64(count) / length
		entropy -= probability * math.Log2(probability)
	}
	return entropy
}
