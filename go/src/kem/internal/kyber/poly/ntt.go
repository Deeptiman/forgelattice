package poly

import (
	"github.com/Deeptiman/forgekey/go/src/kem/internal/kyber/common"
	"github.com/Deeptiman/forgekey/go/src/kem/internal/kyber/math"
	"github.com/Deeptiman/forgekey/go/src/prime"
	"math/big"
)

var zetas = PrecomputeZetas()

func (p *Poly) NTT() {
	k := 0
	for subProblems := common.N / 2; subProblems > 1; subProblems >>= 1 {
		for blocks := 0; blocks < common.N-subProblems; blocks += 2 * subProblems {
			k++
			zeta := int32(zetas[k])
			for j := blocks; j < blocks+subProblems; j++ {
				r := MontgomeryMul(zeta, int32(p.coeffs[j+subProblems]))
				p.coeffs[j+subProblems] = p.coeffs[j] - r
				p.coeffs[j] += r
			}
		}
	}
}

func (p *Poly) InvNTT() {
	k := 127
	nInv := 1441
	for subProblems := 2; subProblems < common.N; subProblems <<= 1 {
		for block := 0; block < common.N-1; block += 2 * subProblems {
			z := zetas[k]
			k--
			for j := block; j < block+subProblems; j++ {
				p.coeffs[j] = Maybe(p.coeffs[j])
				p.coeffs[j+subProblems] = Maybe(p.coeffs[j+subProblems])

				r := p.coeffs[j+subProblems] - p.coeffs[j]
				p.coeffs[j] += p.coeffs[j+subProblems]
				p.coeffs[j+subProblems] = MontgomeryMul(int32(z), int32(r))
			}
		}
	}

	for i := 0; i < common.N; i++ {
		p.coeffs[i] = MontgomeryMul(int32(nInv), int32(p.coeffs[i]))
	}
}

func (p *Poly) MulConvolution(a, b *Poly) {
	k := 64
	for i := 0; i < common.N; i += 4 {
		zeta := zetas[k]
		k++

		// first pair: x² = +zeta
		t0 := MontgomeryMul(int32(a.coeffs[i+1]), int32(b.coeffs[i+1]))
		t0 = MontgomeryMul(int32(t0), int32(zeta))
		t0 += MontgomeryMul(int32(a.coeffs[i]), int32(b.coeffs[i]))

		t1 := MontgomeryMul(int32(a.coeffs[i]), int32(b.coeffs[i+1]))
		t1 += MontgomeryMul(int32(a.coeffs[i+1]), int32(b.coeffs[i]))

		p.coeffs[i] += t0
		p.coeffs[i+1] += t1

		// second pair: x² = -zeta
		t2 := MontgomeryMul(int32(a.coeffs[i+3]), int32(b.coeffs[i+3]))
		t2 = -MontgomeryMul(int32(t2), int32(zeta))
		t2 += MontgomeryMul(int32(a.coeffs[i+2]), int32(b.coeffs[i+2]))

		t3 := MontgomeryMul(int32(a.coeffs[i+2]), int32(b.coeffs[i+3]))
		t3 += MontgomeryMul(int32(a.coeffs[i+3]), int32(b.coeffs[i+2]))

		p.coeffs[i+2] += t2
		p.coeffs[i+3] += t3
	}
}

func PrecomputeZetas() [128]int16 {
	var z [128]int16
	zeta := FindPrimitiveRoot()
	for i := 0; i < common.N/2; i++ {
		exp := math.BitReverse(i)
		v := math.ModPow(zeta, exp, int(common.Q))
		z[i] = MontgomeryMul(int32(v), common.R2modQ)
	}
	return z
}

func FindPrimitiveRoot() int {
	order := uint64(common.N)
	qBig := new(big.Int).SetUint64(order)
	factors := prime.FactorByPollardRho(qBig)

	return int(prime.FindPrimitiveRoots(uint64(common.Q), order, factors))
}
