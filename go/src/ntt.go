package src

import (
	"math/bits"
)

type Decimation string

const (
	Time      Decimation = "Decimation_In_Time"
	Frequency Decimation = "Decimation_In_Frequency"
)

type NTTTable struct {
	// N is the number of coefficient from the approximation polynomial.
	N int
	// Q modulus for the cryptographic computation.
	Q int64
	// PrimitiveRoot of given modulus Q (Nth root of unity).
	PrimitiveRoot int64
	// Twiddles factors for each stage computations.
	Twiddles [][]int64
}

func (n *NTTTable) modMul(a, b, mod int64) int64 {
	res := a * b % mod
	if res < 0 {
		res += mod
	}
	return res
}

func (n *NTTTable) modPow(base, exp, mod int64) int64 {
	res := int64(1)
	for exp > 0 { // binary exponentiation
		// Check if last least significant bit is odd-bit.
		if (exp>>1)&1 == 1 {
			res = n.modMul(res, base, mod)
		}
		base = n.modMul(base, base, mod)
		exp >>= 1 // right to left shift to read through least significant bits.
	}
	return res
}

func toInt64(factors []uint64) []int64 {
	factorInt64 := make([]int64, 0, len(factors))
	for _, factor := range factors {
		factorInt64 = append(factorInt64, int64(factor))
	}
	return factorInt64
}

func (n *NTTTable) isPrimitiveRoot(g, q int64, factors []int64) bool {
	phi := q - 1
	for _, f := range factors {
		if n.modPow(g, phi/f, q) == 1 {
			return false
		}
	}
	return true
}

func (n *NTTTable) FindPrimitiveRoots(factors []uint64) int64 {
	if len(factors) == 0 {
		return -1
	}
	for g := int64(2); g <= 1000; g++ {
		if n.isPrimitiveRoot(g, n.Q, toInt64(factors)) {
			return g
		}
		g++
	}
	return -1
}

// PrecomputeTwiddleFactor pre-calculates the magic-multipliers (twiddle factors) for the NTT.
func (n *NTTTable) PrecomputeTwiddleFactor() [][]int64 {
	// bits.TrailingZeros returns of number of trailing 0 bits in the binary representation of n.
	// And the number of twiddles in each radix stages will be allocated based on number of 0s found.
	problemSize := bits.TrailingZeros(uint(n.N))
	twiddles := make([][]int64, problemSize)
	stage := 0
	for subProblems := 2; subProblems <= n.N; subProblems <<= 1 {
		// Compute magic-multiplier {wm} for the subProblems size.
		wm := n.modPow(n.PrimitiveRoot, int64(n.N/subProblems), n.Q)
		// Allocate number of twiddles by equally spacing required twiddles for the subProblem size.
		//
		//
		// Why equally spaced twiddles?
		//
		// Twiddle factors are precomputed, equally spaced multipliers used in NTT to ensure balanced
		// computations across sub-problems (butterflies). They act as fixed "exchange rates" in each
		// stage, enabling point-wise multiplications with polynomial coefficients. More specifically
		// these twiddles combines pairs of coefficients within groups, facilitating efficient
		// frequency decomposition for fast polynomial operations.
		twiddles[stage] = make([]int64, subProblems/2)
		wi := int64(1)
		for j := 0; j < subProblems/2; j++ {
			twiddles[stage][j] = wi
			wi = n.modMul(wi, wm, n.Q)
		}
		stage++
	}
	return twiddles
}

func (n *NTTTable) PrecomputeTwiddleFactorsByDIF() [][]int64 {
	problemSize := bits.TrailingZeros(uint(n.N))
	twiddles := make([][]int64, problemSize)
	stage := 0
	for subProblems := n.N; subProblems >= 2; subProblems >>= 1 {
		wm := n.modPow(n.PrimitiveRoot, int64(n.N/subProblems), n.Q)
		wmInv := n.modPow(wm, n.Q-2, n.Q)
		twiddles[stage] = make([]int64, subProblems/2)
		wi := int64(1)
		for j := 0; j < subProblems/2; j++ {
			twiddles[stage][j] = wi
			wi = n.modMul(wi, wmInv, n.Q)
		}
		stage++
	}
	return twiddles
}

func (n *NTTTable) BitReverse(coeffs []int64) []int64 {
	result := make([]int64, n.N)
	problemSize := bits.TrailingZeros(uint(n.N))
	for i := 0; i < n.N; i++ {
		rev := 0
		// Overall index reversal is bounded within the ProblemSize to avoid overflow from given N.
		// i as int in Go can be 32bit or 64bit integer, so problemSize (1 >> N) value will keep the
		// overall index swapping in between the bounded range < N.
		for j := 0; j < problemSize; j++ {
			// If jth bit of index i (in binary) is 1, then (problemSize - 1 - j)th bit can be set
			// to 1-bit reverse.
			if (i>>j)&1 == 1 {
				rev |= 1 << (problemSize - 1 - j)
			}
		}
		result[rev] = coeffs[i]
	}
	return result
}

func (n *NTTTable) NTT(coeffs []int64) []int64 {
	stage := 0
	for subProblems := 2; subProblems <= n.N; subProblems <<= 1 {
		stageTwiddles := n.Twiddles[stage]
		for i := 0; i < n.N; i += subProblems {
			for j := 0; j < subProblems/2; j++ {
				wi := stageTwiddles[j]
				u := coeffs[i+j]
				v := coeffs[i+j+subProblems/2]
				// U + V mod Q
				coeffs[i+j] = n.modMul(u+v, 1, n.Q)
				// U - Wi * V mod Q
				coeffs[i+j+subProblems/2] = n.modMul(u-n.modMul(wi, v, n.Q), 1, n.Q)
			}
		}
		stage++
	}
	return coeffs
}

func (n *NTTTable) INTT(coeffs []int64, d Decimation) []int64 {
	switch d {
	case Time:
		return n.InverseNTTByDIT(coeffs)
	case Frequency:
		return n.InverseNTTByDIF(coeffs)
	}
	return []int64{}
}

func (n *NTTTable) InverseNTTByDIF(coeffs []int64) []int64 {
	twiddles := n.PrecomputeTwiddleFactorsByDIF()
	stage := 0
	for subProblems := n.N; subProblems >= 2; subProblems >>= 1 {
		for i := 0; i < n.N; i += subProblems {
			for j := 0; j < subProblems/2; j++ {
				wi := twiddles[stage][j]
				u := coeffs[i+j]
				v := coeffs[i+j+subProblems/2]
				coeffs[i+j] = n.modMul(u+v, 1, n.Q)
				coeffs[i+j+subProblems/2] = n.modMul(u-n.modMul(wi, v, n.Q), 1, n.Q)
			}
		}
		stage++
	}
	return coeffs
}

func (n *NTTTable) InverseNTTByDIT(coeffs []int64) []int64 {

	return []int64{}
}
