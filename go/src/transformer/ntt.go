package transformer

import (
	"math/bits"
)

type Decimation string

const (
	Time      Decimation = "Decimation_In_Time"
	Frequency Decimation = "Decimation_In_Frequency"
)

// NTTTable holds the precomputed parameters and twiddle factors for efficient computation of a Radix-2 NTT.
// It supports both forward (DIT) and inverse (DIF) transform on power-of-2 polynomials modulo Q, as required
// by lattice-based PQC algorithms (Kyber, Dilithium) and homomorphic encryption.
type NTTTable struct {
	// N is the polynomial degree (number of coefficients), must be a power of 2.
	N int
	// Q is the prime modulus for NTT domain (Q ≡ 1 mod 2N).
	Q int64
	// PrimitiveRoot is a primitive N-th root of unity modulo Q (wˆN ≡ 1, order = N).
	PrimitiveRoot int64
	// Twiddles contains precomputed twiddle factors for each stage:
	//
	//  Twiddles[stage][j] = w^(±(N/m)*j) mod Q
	//  - Forward (DIT): wˆ((N/m)*j)
	//	- Inverse (DIF): wˆ(-(N/m)*j)
	// where m = 2^(stage+1) is the group size.
	Twiddles [][]int64
}

// isPrimitiveRoot is the internal method which performs the (Q-1)/gcd(N, Q-1) for each factor to find the multiplicative
// order.
func (n *NTTTable) isPrimitiveRoot(g, q int64, factors []int64) bool {
	phi := q - 1
	for _, f := range factors {
		if n.modPow(g, phi/f, q) == 1 {
			return false
		}
	}
	return true
}

// FindPrimitiveRoots discovers all primitive N-th roots of unity modulo Q. It iterates over candidates in [2, Q) and
// tests each using the Extended Euclidean Algorithm to verify that it generates the full multiplicative order
// (Q-1)/gcd(N, Q-1) and in returns the count of valid primitive roots.
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

// BitReverse performs a perfect shuffle of the indices using bit-reversal permutation. This reorders NTT domain
// coefficients to produce natural-order (NR) output in DIT (forward) NTT or prepares bit-reversed coefficients to
// transform into natural-order (NR) input for DIF (inverse) operation.
//
// # NTT Ordering conventions
//
// Forward NTT(DIT):
//   - NR: Natural input ----> Reversed output (common in FPGA, in-place multiplication)
//   - RN: Reversed input ----> Natural output (
//   - NN: Natural input ----> Natural output (requires bit-reversal on the output)
//
// Reverse INTT(DIF):
//   - NR: Natural input ----> Reversed output
//   - NN: Natural input ----> Natural output (requires bit-reversal on the output)
//   - RN: Reversed input ----> Natural output (in-place, no bit-reversal)
//
// PQC (Kyber, Dilithium) typically uses NR → RN → NN for optimal in-place computation.
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

// NTT (DIT) performs the forward transformation, converting polynomial coefficients from the time domain into
// NTT(frequency) domain. Each output coefficient A[k] is the evaluation form of the input polynomial at the
// k-th Nth root of unity.
//
// Forward NTT: A[k] = a[k] * w(iˆk) mod Q, where w is the primitive N-th root of unity.
func (n *NTTTable) NTT(coeffs []int64) []int64 {
	stage := 0
	coeffsInput := make([]int64, n.N)
	copy(coeffsInput, coeffs)
	for subProblems := 2; subProblems <= n.N; subProblems <<= 1 {
		stageTwiddles := n.Twiddles[stage]
		for i := 0; i < n.N; i += subProblems {
			for j := 0; j < subProblems/2; j++ {
				wi := stageTwiddles[j]
				u := coeffsInput[i+j]
				v := coeffsInput[i+j+subProblems/2]
				// U + V mod Q
				coeffsInput[i+j] = n.modMul(u+v, 1, n.Q)
				// U - Wi * V mod Q
				coeffsInput[i+j+subProblems/2] = n.modMul(u-n.modMul(wi, v, n.Q), 1, n.Q)
			}
		}
		stage++
	}
	return coeffsInput
}

// INTT performs the transformation to recover the original polynomial coefficients in the time domain. After the
// forward NTT (DIT), the coefficients are in the NTT (frequency) domain and mathematically coefficients are in
// evaluation form at the N-th roots of unity: A[k]=a(wˆk) = Σ a[i] * wˆ(i*k) mod Q, where w is the primitive
// N-th root of unity.
//
// # After Inverse NTT
//
// a[i] = (1/N) * Σ A[k] * ω^(-i*k)  // Back to original coefficients
func (n *NTTTable) INTT(coeffs []int64, d Decimation) []int64 {
	switch d {
	case Time:
		return n.InverseNTTByDIT(coeffs)
	case Frequency:
		return n.InverseNTTByDIF(coeffs)
	}
	return []int64{}
}

// InverseNTTByDIF computes the inverse transformation in frequency domain. The inverse process do not need any
// bit-reversal and optimal for FPGA.
func (n *NTTTable) InverseNTTByDIF(coeffs []int64) []int64 {
	twiddles := n.PrecomputeTwiddleFactorsByDIF()
	coeffsInput := make([]int64, n.N)
	copy(coeffsInput, coeffs)
	stage := 0
	for subProblems := n.N; subProblems >= 2; subProblems >>= 1 {
		for i := 0; i < n.N; i += subProblems {
			for j := 0; j < subProblems/2; j++ {
				wi := twiddles[stage][j]
				u := coeffsInput[i+j]
				v := coeffsInput[i+j+subProblems/2]
				coeffsInput[i+j] = n.modMul(u+v, 1, n.Q)
				coeffsInput[i+j+subProblems/2] = n.modMul(u-n.modMul(wi, v, n.Q), 1, n.Q)
			}
		}
		stage++
	}
	// Final scaling: multiply by N^(-1) mod Q
	nInv := n.modPow(int64(n.N), n.Q-2, n.Q)
	for i := 0; i < n.N; i++ {
		coeffsInput[i] = n.modMul(coeffsInput[i], nInv, n.Q)
	}
	return coeffsInput
}

// InverseNTTByDIT computes the inverse transformation in time domain.
func (n *NTTTable) InverseNTTByDIT(coeffs []int64) []int64 {

	return []int64{}
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
