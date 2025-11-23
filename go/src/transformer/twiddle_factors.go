package transformer

import (
	"github.com/Deeptiman/forgekey/go/src/utils"
	"math/bits"
)

// PrecomputeTwiddleFactor pre-calculates the magic-multipliers (twiddle factors) for the NTT.
func (n *NTTTable) PrecomputeTwiddleFactor() [][]int64 {
	// problemSize computes log₂(N), the number of NTT stages (sub-problems), computed with bits.TrailingZeros
	// for any power of 2 N.
	//
	// bits.TrailingZeros returns of number of trailing 0 bits in the binary representation of n.
	// And the number of twiddles in each radix stages will be allocated based on number of 0s found.
	//
	// This returns exact number of butterfly stages for Radix-2 NTT.
	//
	// Example:
	// 	N = 16 -> log₂(16) = 4 --> 4 sub-problems (m=2, 4, 8, 16)
	problemSize := bits.TrailingZeros(uint(n.N))
	twiddles := make([][]int64, problemSize)
	stage := 0
	for subProblems := 2; subProblems <= n.N; subProblems <<= 1 {
		// Compute magic-multiplier {wm} for the subProblems size.
		wm := utils.ModPow(n.PrimitiveRoot, int64(n.N/subProblems), n.Q)
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
			wi = utils.ModMul(wi, wm, n.Q)
		}
		stage++
	}
	return twiddles
}

// PrecomputeTwiddleFactorsByDIF precomputes all twiddle factors required for the DIF (inverse) NTT.
// This eliminates expensive modular exponentiation at runtime and enables constant-time access via read-only
// BRAM, achieving high-throughput pipelined NTT computation on FPGA.
func (n *NTTTable) PrecomputeTwiddleFactorsByDIF() [][]int64 {
	// problemSize computes log₂(N), the number of NTT stages (sub-problems), computed with bits.TrailingZeros
	// for any power of 2 N.
	//
	// bits.TrailingZeros returns of number of trailing 0 bits in the binary representation of n.
	// And the number of twiddles in each radix stages will be allocated based on number of 0s found.
	//
	// This returns exact number of butterfly stages for Radix-2 NTT.
	//
	// Example:
	// 	N = 16 -> log₂(16) = 4 --> 4 sub-problems (m=2, 4, 8, 16)
	problemSize := bits.TrailingZeros(uint(n.N))
	twiddles := make([][]int64, problemSize)
	stage := 0
	for subProblems := n.N; subProblems >= 2; subProblems >>= 1 {
		wm := utils.ModPow(n.PrimitiveRoot, int64(n.N/subProblems), n.Q)
		wmInv := utils.ModPow(wm, n.Q-2, n.Q)
		twiddles[stage] = make([]int64, subProblems/2)
		wi := int64(1)
		for j := 0; j < subProblems/2; j++ {
			twiddles[stage][j] = wi
			wi = utils.ModMul(wi, wmInv, n.Q)
		}
		stage++
	}
	return twiddles
}

// PrecomputeInverseTwiddleFactors precomputes all the inverse twiddle factors w^(-j) required for inverse NTT.
//
// - w^(-1) = wˆ(Q-2) mod Q (Fermat's Little Theorem).
// - For each stage, computes wˆ(-(N/m)*j) where m = 2ˆ(stage + 1).
// - Used by both DIT and DIF inverse NTT.
// - Stored in BRAM for constant-time access on FPGA.
func (n *NTTTable) PrecomputeInverseTwiddleFactors() [][]int64 {
	problemSize := bits.TrailingZeros(uint(n.N))
	twiddles := make([][]int64, problemSize)
	stage := 0
	for subProblems := 2; subProblems <= n.N; subProblems <<= 1 {
		wm := utils.ModPow(n.PrimitiveRoot, int64(n.N/subProblems), n.Q)
		wmInv := utils.ModPow(wm, n.Q-2, n.Q)
		twiddles[stage] = make([]int64, subProblems/2)
		wi := int64(1)
		for j := 0; j < subProblems/2; j++ {
			twiddles[stage][j] = wi
			wi = utils.ModMul(wi, wmInv, n.Q)
		}
		stage++
	}
	return twiddles
}
