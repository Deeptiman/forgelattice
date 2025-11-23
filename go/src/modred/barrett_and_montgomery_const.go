package modred

import "math/big"

func barrettMu32(q uint64) uint64 {
	return (uint64(1) << 32) / q
}

func barrettMu64(q uint64) uint64 {
	maxBit := ^uint64(0) //2⁶⁴ - 1
	return maxBit / q
}

func computeBarrettRedConstant(q uint64) barrettConstant {
	return barrettConstant{mu32: barrettMu32(q), mu64: barrettMu64(q)}
}

// ComputeMontgomeryConstants
//
//	---> R = 2⁶⁴
//
//	---> qInv = (-q⁻¹) mod R where inverse is q⁻¹ mod R.
//
//	---> r2 = R² mod q
func computeMontgomeryConstants(q uint64) montgomeryConstants {
	qBig := new(big.Int).SetUint64(q)
	R := new(big.Int).Lsh(big.NewInt(1), 64) // Maximum inflated modulus 2⁶⁴

	// qInv = -q⁻¹ mod 2⁶⁴
	qInv := new(big.Int).ModInverse(qBig, R)
	qInv.Neg(qInv).Mod(qInv, R)

	// r2 = R² mod q
	R2Big := new(big.Int).Mul(R, R)
	R2Big.Mod(R2Big, qBig)
	r2 := R2Big.Uint64()
	return montgomeryConstants{qInv.Uint64(), r2}
}
