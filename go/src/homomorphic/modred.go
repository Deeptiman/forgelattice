package homomorphic

import (
	"math/big"
	"math/bits"
)

var (
	// HEQ ...
	HEQ uint64 = 0x0FFFFFFFFFFFFFFB // < 2^60 (homomorphic ~60-bit modulus)
)

type HEInt struct {
	Q    uint64
	QInv uint64

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

func (h HEInt) BarrettRedWith32bit(x uint64) uint64 {
	hi, lo := bits.Mul64(x, h.barrettConstant.mu32)
	t := hi<<32 | lo>>32

	r := x - t*h.Q
	if r >= h.Q {
		r -= h.Q
	}
	return r
}

func (h HEInt) BarrettRedWith64bit(x uint64) uint64 {
	// 1) t = floor(x * Mu64 / 2⁶⁴)
	// Mul64 returns 128-bit product: hi:lo = x * Mu
	hi, _ := bits.Mul64(x, h.barrettConstant.mu64) // hi is exactly floor(x*Mu64 / 2⁶⁴)

	// 2) r = x - hi*Q
	r := x - hi*h.Q

	// 3) r is now in [0, 2q) (for typical HE standard modulus range)
	// so at most two subtractions normalize into [0, q).
	for r >= h.Q {
		r -= h.Q
	}
	return r
}

// MontgomeryMul ...
func (h HEInt) MontgomeryMul(a, b uint64) uint64 {
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
	m0 := lowBits * h.montConstants.qInv

	// Extract high bits from m * q
	mHigh, mLo := bits.Mul64(m0, h.Q)

	// add low parts, capture carry
	_, carry := bits.Add64(lowBits, mLo, 0)

	// add high parts plus carry
	sumHi, _ := bits.Add64(highBits, mHigh, carry)

	u := sumHi

	// Check if overflow occurs with the addition above the given modulo Q.
	if u >= h.Q {
		u -= h.Q
	}
	return u
}

// ToMontgomery ...
func (h HEInt) ToMontgomery(x uint64) uint64 {
	return h.MontgomeryMul(x%h.Q, h.montConstants.r2)
}

// FromMontgomery ...
func (h HEInt) FromMontgomery(x uint64) uint64 {
	return h.MontgomeryMul(x, 1)
}

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
