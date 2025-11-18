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

	Kyber_Q = 3329 //
)

var (
	R  = new(big.Int).Lsh(big.NewInt(1), 64) // Maximum inflated modulus 2⁶⁴
	R2 = new(big.Int).Mul(R, R)
)

type ModRed struct {
	Q             uint64
	montConstants montgomeryConstants
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

// MontgomeryMulWithKyberPQC ...
//
// Source: https://github.com/cloudflare/circl/blob/main/pke/kyber/internal/common/field.go#L4
func (r *ModRed) MontgomeryMulWithKyberPQC(a, b int32) int16 {
	x := a * b
	// Why CIRCL uses 16-bit Montgomery for Kyber?
	// - Kyber q = 3329 < 2¹², so its easily fits in a 16-bit word. Choosing R = 2¹⁶ is natural because its
	// the next convenient machine word power-of-two that's large than 3329.
	// - The standard 16-bit Montgomery reduction for Kyber can be written using int32 multiples and >> 16
	// shifts.
	// - With R = 2¹⁶ reduction can exploit simple shifts and 16/32-bit arithmetic to implement Montgomery
	// reduction cheaply.
	//
	// 	R = 2¹⁶
	//
	//	q' := 62209 = q⁻¹ mod R.
	m := int16(x * 62209)
	return int16(uint32(x-int32(m)*int32(Kyber_Q)) >> 16)
}

// ToMontgomeryWithKyberPQC ...
func (r *ModRed) ToMontgomeryWithKyberPQC(x int32) int16 {
	// q = 3329
	// 1353 = R² mod q.
	return r.MontgomeryMulWithKyberPQC(x, 1353)
}

func (a Algorithm) WithModRed(q uint64) *ModRed {
	switch a {
	case Kyber:
		// Works with Barrett
	case Dilithium:
		// Works with Montgomery
	case Generic:
		// Apply generic modular reductions comparing modulus Q to apply Barrett or Montgomery.
	}
	return &ModRed{q, computeMontgomeryConstants(q)}
}
