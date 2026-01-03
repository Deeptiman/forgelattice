package kyber

import (
	"github.com/Deeptiman/forgekey/go/src/prime"
	"math/big"
)

func (p *Poly) NTT() {
	k := 0
	for subProblems := N / 2; subProblems > 1; subProblems >>= 1 {
		for blocks := 0; blocks < N-subProblems; blocks += 2 * subProblems {
			k++
			zeta := int32(zetas[k])
			for j := blocks; j < blocks+subProblems; j++ {
				t := MontgomeryMul(zeta, int32(p[j+subProblems]))
				p[j+subProblems] = p[j] - t
				p[j] += t
			}
		}
	}
}

func (p *Poly) InvNTT() {
	k := 127
	nInv := 1441
	for subProblems := 2; subProblems < N; subProblems <<= 1 {
		for block := 0; block < N-1; block += 2 * subProblems {
			z := zetas[k]
			k--
			for j := block; j < block+subProblems; j++ {
				p[j] = maybeReduce(p[j])
				p[j+subProblems] = maybeReduce(p[j+subProblems])

				t := p[j+subProblems] - p[j]
				p[j] += p[j+subProblems]
				p[j+subProblems] = MontgomeryMul(int32(z), int32(t))
			}
		}
	}

	for i := 0; i < N; i++ {
		p[i] = MontgomeryMul(int32(nInv), int32(p[i]))
	}
}

func PrecomputeKyberZetas() [128]int16 {
	var z [128]int16
	zeta := FindPrimitiveRoot()
	for i := 0; i < N/2; i++ {
		exp := BitReverse(i)
		v := ModPow(zeta, exp, int(Q))
		z[i] = MontgomeryMul(int32(v), R2modQ)
	}
	return z
}

func FindPrimitiveRoot() int {
	order := uint64(N)
	qBig := new(big.Int).SetUint64(order)
	factors := prime.FactorByPollardRho(qBig)

	return int(prime.FindPrimitiveRoots(uint64(Q), order, factors))
}
