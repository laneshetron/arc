package fec

import "math"

// Sizing (spec §11.2): how many repairs a block needs, and how deep to
// interleave, from the measured loss rate and mean burst length.

// RepairsFor returns how many repairs a block of k sources needs so that
// more losses than repairs, among its k+m packets lost independently with
// probability loss, happen with probability at most target. The count is
// capped at k/2 (50% overhead) and MaxM; it is zero when loss is zero.
func RepairsFor(k int, loss, target float64) int {
	if k < 1 || loss <= 0 {
		return 0
	}
	limit := min(max(k/2, 1), MaxM)
	for m := 1; m <= limit; m++ {
		if binomialTail(k+m, loss, m) <= target {
			return m
		}
	}
	return limit
}

// binomialTail returns P(X > m) for X ~ Binomial(n, p).
func binomialTail(n int, p float64, m int) float64 {
	cdf, term := 0.0, math.Pow(1-p, float64(n)) // P(X = 0)
	for x := 0; x <= m && x <= n; x++ {
		cdf += term
		term *= float64(n-x) / float64(x+1) * p / (1 - p)
	}
	return max(1-cdf, 0)
}

// DepthFor returns the interleaving depth for a mean burst length: about
// one burst's worth, so a typical burst costs each block one packet,
// within MaxDepth.
func DepthFor(meanBurst float64) int {
	return min(max(int(math.Round(meanBurst)), 1), 8)
}
