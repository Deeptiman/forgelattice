package poly

import (
	"github.com/Deeptiman/forgelattice/go/src/sign/dilithium/internal/common"
	"github.com/Deeptiman/forgelattice/go/src/sign/dilithium/internal/mathutils"
	"github.com/Deeptiman/forgelattice/go/src/sign/dilithium/internal/reduction"
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
	order := uint64(2 * common.N)
	qBig := new(big.Int).SetUint64(order)
	factors := mathutils.FactorByPollardRho(qBig)
	return int(mathutils.FindPrimitiveRoots(uint64(common.Q), order, factors))
}

func PrecomputeZetas() [256]uint32 {
	zeta := FindPrimitiveRoot()
	R := big.NewInt(int64(common.R2modQ)) // 4193792
	q := big.NewInt(int64(common.Q))      // 8380417
	var z [256]uint32
	for i := 0; i < 256; i++ {
		pow := mathutils.ModPow(zeta, mathutils.BitReverse(i), common.Q)
		powBig := big.NewInt(int64(pow))
		powBig.Mul(powBig, R)
		powBig.Mod(powBig, q)
		z[i] = uint32(powBig.Int64())
	}
	return z
}

func PrecomputeInverseZetas() [256]uint32 {
	zeta := FindPrimitiveRoot()
	invZeta := mathutils.ModPow(zeta, common.Q-2, common.Q)
	R := big.NewInt(int64(common.R2modQ)) // 4193792
	q := big.NewInt(int64(common.Q))      // 8380417

	var z [256]uint32
	for i := 0; i < 256; i++ {
		pow := mathutils.ModPow(invZeta, -(mathutils.BitReverse(255-i) - 256), common.Q)
		powBig := big.NewInt(int64(pow))
		powBig.Mul(powBig, R)
		powBig.Mod(powBig, q)
		z[i] = uint32(powBig.Int64())
	}
	return z
}

func (v Vec) InvNTT() {
	for i := 0; i < len(v); i++ {
		v[i].InvNTT()
	}
}

func (v Vec) NTT() {
	for i := 0; i < len(v); i++ {
		v[i].NTT()
	}
}

func (p *Poly) NTT() {
	m := 0
	for l := common.N / 2; l > 0; l >>= 1 {
		for start := 0; start < common.N-l; start += 2 * l {
			m++
			z := uint64(Zetas[m])
			for j := start; j < start+l; j++ {
				r := reduction.Le2Q(z * uint64(p.coeffs[j+l]))
				// Butterfly update:
				//
				// 	(a, b) --> (a + r, a - r)
				//
				// This combines the lower and upper halves of the block.
				//
				// 2*Q used in CIRCL NTT, mainly beneficial for modular-reduction of the coeffs in further
				// computation in later stages in ML-DSA schemes.
				p.coeffs[j+l] = p.coeffs[j] + (2*common.Q - r) // Cooley--Tukey butterfly
				p.coeffs[j] += r
			}
		}
	}
}

func (p *Poly) InvNTT() {
	m := 0
	for l := 1; l < common.N; l <<= 1 {
		for start := 0; start < common.N-l; start += 2 * l {
			z := uint64(InvZetas[m])
			m++
			for j := start; j < start+l; j++ {
				t := p.coeffs[j] // Gentleman--Sande butterfly
				p.coeffs[j] = t + p.coeffs[j+l]
				t += 256*common.Q - p.coeffs[j+l]
				p.coeffs[j+l] = reduction.Le2Q(z * uint64(t))
			}
		}
	}

	for j := 0; j < common.N; j++ {
		// ROver256 = 41978 = (256)⁻¹ R²
		p.coeffs[j] = reduction.Le2Q(common.ROver256 * uint64(p.coeffs[j]))
	}
}

func (p *Poly) InvNttGeneric() {
	k := 0 // Index into InvZetas
	for l := uint(1); l < common.N; l <<= 1 {
		for offset := uint(0); offset < common.N-l; offset += 2 * l {
			zeta := uint64(InvZetas[k])
			k++
			for j := offset; j < offset+l; j++ {
				t := p.coeffs[j] // Gentleman--Sande butterfly
				p.coeffs[j] = t + p.coeffs[j+l]
				t += 256*common.Q - p.coeffs[j+l]
				p.coeffs[j+l] = reduction.Le2Q(zeta * uint64(t))
			}
		}
	}

	for j := uint(0); j < common.N; j++ {
		p.coeffs[j] = reduction.Le2Q(common.ROver256 * uint64(p.coeffs[j]))
	}
}

func montReduceLe2Q(x uint64) uint32 {
	// Qinv = 4236238847 = -(q⁻¹) mod 2³²
	m := uint64(uint32(x)*common.QInv) & 0xffffffff
	return uint32((x + m*uint64(common.Q)) >> 32)
}
