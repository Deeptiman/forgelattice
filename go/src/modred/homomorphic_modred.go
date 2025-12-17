package modred

import "math/bits"

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
	hi, _ := bits.Mul64(x, h.barrettConstant.mu64)
	t := hi // hi is exactly floor(x*Mu64 / 2⁶⁴)

	// 2) r = x - t*Q
	r := x - t*h.Q

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
