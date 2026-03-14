package poly

import (
	"github.com/Deeptiman/forgekey/go/src/prime"
	"github.com/Deeptiman/forgekey/go/src/sign/internal/dilithium/math"
	"github.com/Deeptiman/forgekey/go/src/sign/internal/dilithium/reduction"
	"math/big"
)

var Zetas = PrecomputeZetas()

var InvZetas = PrecomputeInverseZetas()

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
	order := uint64(2 * N)
	qBig := new(big.Int).SetUint64(order)
	factors := prime.FactorByPollardRho(qBig)
	return int(prime.FindPrimitiveRoots(uint64(Q), order, factors))
}

func PrecomputeZetas() [256]uint32 {
	zeta := FindPrimitiveRoot()
	R := big.NewInt(int64(R2modQ)) // 4193792
	q := big.NewInt(int64(Q))      // 8380417
	var z [256]uint32
	for i := 0; i < 256; i++ {
		pow := math.ModPow(zeta, math.BitReverse(i), Q)
		powBig := big.NewInt(int64(pow))
		powBig.Mul(powBig, R)
		powBig.Mod(powBig, q)
		z[i] = uint32(powBig.Int64())
	}
	return z
}

func PrecomputeInverseZetas() [256]uint32 {
	zeta := FindPrimitiveRoot()
	invZeta := math.ModPow(zeta, Q-2, Q)
	R := big.NewInt(int64(R2modQ)) // 4193792
	q := big.NewInt(int64(Q))      // 8380417

	var z [256]uint32
	for i := 0; i < 256; i++ {
		pow := math.ModPow(invZeta, -(math.BitReverse(255-i) - 256), Q)
		powBig := big.NewInt(int64(pow))
		powBig.Mul(powBig, R)
		powBig.Mod(powBig, q)
		z[i] = uint32(powBig.Int64())
	}
	return z
}

func (p *Poly) NTT() {
	m := 0
	for l := N / 2; l > 0; l >>= 1 {
		for start := 0; start < N-l; start += 2 * l {
			z := Zetas[m]
			m++
			for j := start; j < start+l; j++ {
				r := reduction.MontgomeryMul(z, p.coeffs[j+l])
				// Butterfly update:
				//
				// 	(a, b) --> (a + r, a - r)
				//
				// This combines the lower and upper halves of the block.
				//
				// 2*Q used in CIRCL NTT, mainly beneficial for modular-reduction of the coeffs in further
				// computation in later stages in ML-DSA schemes.
				p.coeffs[j+l] = p.coeffs[j] + (2*Q - r) // Cooley--Tukey butterfly
				p.coeffs[j] += r
			}
		}
	}
}

func (p *Poly) InvNTT() {
	m := 0
	for l := 1; l < N; l <<= 1 {
		for start := 0; start < N-l; start += 2 * l {
			z := InvZetas[m]
			m++
			for j := start; j < start+l; j++ {
				t := p.coeffs[j] // Gentleman--Sande butterfly
				p.coeffs[j] = t + p.coeffs[j+l]
				t += 256*Q - p.coeffs[j+l]
				p.coeffs[j+l] = reduction.MontgomeryMul(z, t)
			}
		}
	}

	for j := 0; j < N; j++ {
		// ROver256 = 41978 = (256)⁻¹ R²
		p.coeffs[j] = reduction.MontgomeryMul(ROver256, p.coeffs[j])
	}
}
