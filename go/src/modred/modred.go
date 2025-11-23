package modred

import (
	"math/big"
)

type Algorithm string

const (
	Kyber     Algorithm = "PQC_Kyber"
	Dilithium Algorithm = "PQC_Dilithium"
	Generic   Algorithm = "Homomorphic_Encryption"
)

var (
	R  = new(big.Int).Lsh(big.NewInt(1), 64) // Maximum inflated modulus 2⁶⁴
	R2 = new(big.Int).Mul(R, R)
)

type ModRed struct {
	Q               uint64
	Dilithium_QInv  uint32
	montConstants   montgomeryConstants
	barrettConstant barrettConstant
}

type barrettConstant struct {
	mu32 uint64
	mu64 uint64
}

type montgomeryConstants struct {
	qInv uint64 // qInv = -q^{-1} mod 2^64
	r2   uint64 // R^2 mod q
}

func computeMu64(q uint64) uint64 {
	maxBit := ^uint64(0) //2⁶⁴ - 1
	return maxBit / q
}

func computeBarrettRedConstant(q uint64) barrettConstant {
	return barrettConstant{mu32: (uint64(1) << 32) / q, mu64: computeMu64(q)}
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

	// qInv = -q⁻¹ mod 2⁶⁴
	qInv := new(big.Int).ModInverse(qBig, R)
	qInv.Neg(qInv).Mod(qInv, R)

	// r2 = R² mod q
	R2Big := new(big.Int).Mul(R, R)
	R2Big.Mod(R2Big, qBig)
	r2 := R2Big.Uint64()
	return montgomeryConstants{qInv.Uint64(), r2}
}

func (a Algorithm) ToModRed(q uint64) *ModRed {
	r := &ModRed{Q: q}
	switch a {
	case Kyber:
		// TODO: Works with Barrett
	case Dilithium:
		r.Dilithium_QInv = computeDilithiumRedConstant()
	case Generic:
		// TODO: Apply generic modular reductions comparing modulus Q to apply Barrett or Montgomery.
		r.montConstants = computeMontgomeryConstants(q)
		r.barrettConstant = computeBarrettRedConstant(q)
	}
	return r
}
