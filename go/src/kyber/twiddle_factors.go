package kyber

import (
	"github.com/Deeptiman/forgekey/go/src/prime"
	"math/big"
)

func PrecomputeKyberZetas() [128]int16 {
	zetas := [128]int16{}
	zeta := FindPrimitiveRoot()
	for i := 0; i < N/2; i++ {
		exp := BitReverse(i)
		v := ModPow(zeta, exp, int(Q))
		zetas[i] = ToMontgomeryWithKyber(int32(v))
	}
	return zetas
}

func FindPrimitiveRoot() int {
	order := uint64(256)
	qBig := new(big.Int).SetUint64(order)
	factors := prime.FactorByPollardRho(qBig)

	return int(prime.FindPrimitiveRoots(uint64(Q), order, factors))
}
