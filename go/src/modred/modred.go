package modred

import (
	"math/big"
	"math/bits"
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
	Q              uint64
	Dilithium_QInv uint32
	montConstants  montgomeryConstants
}

type montgomeryConstants struct {
	qInv uint64
	r2   uint64
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
	qInv := new(big.Int).ModInverse(qBig, R) // qInv = q⁻¹ mod 2⁶⁴
	R2.Mod(R2, qBig)
	return montgomeryConstants{qInv.Uint64(), R2.Uint64()}
}

// MontgomeryMul ...
func (r *ModRed) MontgomeryMul(a, b uint64) uint64 {
	// 128-bits product and return highBit, lowBit t = bits.Mul64(a, b)
	highBits, lowBits := bits.Mul64(a, b)
	// [ 128 ......................... 64 | 63 ......................... 0 ]
	//	HIGH 64 bits                       LOW 64 bits
	//
	// Low 64 bits → the bottom half
	// (least-significant 64 bits, bits 0–63)
	//
	// High 64 bits -> the top half
	// (most-significant 64 bits, bits 64-127)
	//
	// m = (lowBits * qInv) mod R (since multiplication modulo R is low 64 bit)
	m := lowBits * r.montConstants.qInv

	// Extract high bits from m * q
	mHigh, _ := bits.Mul64(m, r.Q)

	u := highBits - mHigh + r.Q
	// Check if overflow occurs with the addition above the given modulo Q.
	if u >= r.Q {
		u -= r.Q
	}
	return u
}

// ToMontgomery ...
func (r *ModRed) ToMontgomery(x uint64) uint64 {
	return r.MontgomeryMul(x, r.montConstants.r2)
}

// FromMontgomery ...
func (r *ModRed) FromMontgomery(x uint64) uint64 {
	return r.MontgomeryMul(x, 1)
}

func (a Algorithm) ToModRed(q uint64) *ModRed {
	montRed := &ModRed{Q: q, montConstants: computeMontgomeryConstants(q)}
	switch a {
	case Kyber:
		// TODO: Works with Barrett
	case Dilithium:
		// TODO: Works with Montgomery
		montRed.Dilithium_QInv = computeDilithiumRedConstant()
	case Generic:
		// TODO: Apply generic modular reductions comparing modulus Q to apply Barrett or Montgomery.
	}
	return montRed
}
