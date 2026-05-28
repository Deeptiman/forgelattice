package poly

import (
	"github.com/Deeptiman/forgelattice/go/src/kem/kyber/internal/common"
	"github.com/Deeptiman/forgelattice/go/src/kem/kyber/internal/mathutils"
	"github.com/Deeptiman/forgelattice/go/src/kem/kyber/internal/reduction"
	"math/big"
)

var zetas = PrecomputeZetas()

// NTT transforms the polynomial from coefficient form into the NTT (frequency) domain using an in-place
// Cooley-Tukey radix-2 algorithm.
func (p *Poly) NTT() {
	// k indexes into the precomputed table of twiddle factors (zetas).
	// Each stage of the NTT consumes a fixed number of roots.
	k := 0

	// The outer loop controls the size of each sub-problem.
	// It starts with N/2 and halves each round:
	//
	//	N/2, N/4, N/8, ...., 2
	//
	// Each iteration of sub-problem represents one NTT stage.
	for subProblems := common.N / 2; subProblems > 1; subProblems >>= 1 {

		// The polynomial is divided into blocks of size 2*subProblems.
		for blocks := 0; blocks < common.N-subProblems; blocks += 2 * subProblems {
			k++
			// zeta determines how the upper half of the block is rotated.
			zeta := int32(zetas[k])

			// Perform radix-2 butterfly operations within the block.
			for j := blocks; j < blocks+subProblems; j++ {

				// Multiply the upper element by the twiddle factor using Montgomery
				// multiplication (mod Q).
				r := reduction.MontgomeryMul(zeta, int32(p.coeffs[j+subProblems]))

				// Butterfly update:
				//
				// 	(a, b) --> (a + r, a - r)
				//
				// This combines the lower and upper halves of the block.
				p.coeffs[j+subProblems] = p.coeffs[j] - r
				p.coeffs[j] += r
			}
		}
	}
}

// InvNTT applies the inverse number-theoretic transform converting the polynomial from the NTT domain
// back to coefficient form and normalizing by N⁻¹ modulo Q.
func (p *Poly) InvNTT() {
	// k indexes the precomputed inverse twiddle factors (zetas) consumed in reverse order
	// compared to the forward NTT.
	k := 127

	// nInv is N⁻¹ mod Q.
	// It is applied at the end of the INTT to normalize the inverse transformation.
	nInv := 1441

	// The outer loop grows the sub-problem size:
	//
	// 2, 4, 8, ...., N
	//
	// This reverse the decomposition performed by the forward NTT.
	for subProblems := 2; subProblems < common.N; subProblems <<= 1 {
		// Process the polynomial in block of 2*subProblems.
		for block := 0; block < common.N-1; block += 2 * subProblems {
			// Load the next inverse twiddle factors.
			z := zetas[k]
			k--

			// Perform inverse radix-2 butterfly operations.
			for j := block; j < block+subProblems; j++ {

				// Ensure coefficients are in a safe centered range before arithmetic to prevent
				// overflow.
				p.coeffs[j] = reduction.Maybe(p.coeffs[j])
				p.coeffs[j+subProblems] = reduction.Maybe(p.coeffs[j+subProblems])

				// Inverse butterfly:
				//
				// 	(a, b) --> (a + b, z * (b - a))
				//
				// This reverse the mixing performed in the forward NTT.
				r := p.coeffs[j+subProblems] - p.coeffs[j]
				p.coeffs[j] += p.coeffs[j+subProblems]
				p.coeffs[j+subProblems] = reduction.MontgomeryMul(int32(z), int32(r))
			}
		}
	}

	// Final normalization:
	//
	// The inverse NTT recovers the original coefficients scaled by N.
	// Multiply each coefficient by N⁻¹ mod Q to obtain the result.
	for i := 0; i < common.N; i++ {
		p.coeffs[i] = reduction.MontgomeryMul(int32(nInv), int32(p.coeffs[i]))
	}
}

// PointWiseMul performs base (pointwise) multiplication of two polynomial already in the NTT domain and
// producing a product that remains in NTT domain.
//
// The input a and b must already be transformed by NTT(). This function multiplies corresponding NTT
// coefficients using negacyclic base multiplication with precomputed roots of unity (zetas).
//
// The polynomial is processed in blocks of four coefficients corresponding to two degree-1 polynomials.
// Each block is reduced modulo x² ± zeta where sign and root are determined by the NTT structure.
//
// The result remains in the NTT domain and must be transformed back to coefficient form using InvNTT().
func (p *Poly) PointWiseMul(a, b *Poly) {
	k := 64
	// Core idea: Once two polynomials are in the NTT domain, multiplication reduces to independent local
	// products. No further transform stages, block mixing or coefficient shuffling are required, pointwise
	// multiplication is sufficient.
	for i := 0; i < common.N; i += 4 {
		zeta := zetas[k]
		k++

		// first pair: x² = +zeta
		t0 := reduction.MontgomeryMul(int32(a.coeffs[i+1]), int32(b.coeffs[i+1]))
		t0 = reduction.MontgomeryMul(int32(t0), int32(zeta))
		t0 += reduction.MontgomeryMul(int32(a.coeffs[i]), int32(b.coeffs[i]))

		t1 := reduction.MontgomeryMul(int32(a.coeffs[i]), int32(b.coeffs[i+1]))
		t1 += reduction.MontgomeryMul(int32(a.coeffs[i+1]), int32(b.coeffs[i]))

		p.coeffs[i] += t0
		p.coeffs[i+1] += t1

		// second pair: x² = -zeta
		t2 := reduction.MontgomeryMul(int32(a.coeffs[i+3]), int32(b.coeffs[i+3]))
		t2 = -reduction.MontgomeryMul(int32(t2), int32(zeta))
		t2 += reduction.MontgomeryMul(int32(a.coeffs[i+2]), int32(b.coeffs[i+2]))

		t3 := reduction.MontgomeryMul(int32(a.coeffs[i+2]), int32(b.coeffs[i+3]))
		t3 += reduction.MontgomeryMul(int32(a.coeffs[i+3]), int32(b.coeffs[i+2]))

		p.coeffs[i+2] += t2
		p.coeffs[i+3] += t3
	}
}

// PrecomputeZetas generates the table of NTT twiddle factors (root of unity) in Montgomery form indexed
// in bit-reversed order.
func PrecomputeZetas() [128]int16 {
	var z [128]int16

	// Find the primitive root modulo Q.
	// This value generates the multiplicative subgroup used by the NTT.
	zeta := FindPrimitiveRoot()

	// Precompute N/2 twiddle factors.
	//
	// The NTT requires root of unity ordered in bit-reversed index order, so that butterfly
	// stages can consume them sequentially without explicit bit reversal during transform.
	for i := 0; i < common.N/2; i++ {

		// Compute the bit-reversed exponent.
		// This determines the order in which roots are used by the NTT.
		exp := mathutils.BitReverse(i)

		// Compute zeta^exp mod Q
		v := mathutils.ModPow(zeta, exp, int(common.Q))

		// Convert the root into Montgomery representation.
		// Storing zetas in Montgomery form allows all NTT multiplications to use
		// MontgomeryMul without additional conversions.
		z[i] = reduction.MontgomeryMul(int32(v), common.R2modQ)
	}
	return z
}

// FindPrimitiveRoot computes the Nth root of unity modulo Q, used to generate the twiddle factors
// required by the NTT.
func FindPrimitiveRoot() int {
	// The NTT requires a primitive Nth root of unity modulo Q.
	//
	//   z^N ≡ 1 (mod Q)
	//   z^k ≠ 1 (mod Q) for all 0 < k < N
	//
	// z is chosen so that its powers cycle through exactly N distinct values which what makes the NTT
	// work and be invertible. (In short: z sets the twiddle factor order of elements).
	order := uint64(common.N)
	qBig := new(big.Int).SetUint64(order)
	factors := mathutils.FactorByPollardRho(qBig)
	return int(mathutils.FindPrimitiveRoots(uint64(common.Q), order, factors))
}
