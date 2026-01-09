package reduction

import "github.com/Deeptiman/forgekey/go/src/kem/internal/kyber/common"

// MontgomeryMul computes a . b . R⁻¹ mod Q using 16-bit Montgomery reduction.
//
// This implementation follows the Kyber reference approach as used in CIRCL:
// https://github.com/cloudflare/circl/blob/main/pke/kyber/internal/common/field.go
func MontgomeryMul(a, b int32) int16 {
	// Why CIRCL uses 16-bit Montgomery for Kyber?
	// - Kyber q = 3329 < 2¹², so its easily fits in a 16-bit word. Choosing R = 2¹⁶ is natural because its
	// the next convenient machine word power-of-two that's larger than 3329.
	// - The standard 16-bit Montgomery reduction for Kyber can be written using int32 multiples and >> 16
	// shifts.
	// - With R = 2¹⁶ reduction can exploit simple shifts and 16/32-bit arithmetic to implement Montgomery
	// reduction cheaply.
	//
	// Precomputed constants:
	// 	- R = 2¹⁶
	//	- QInv := 62209 = q⁻¹ mod R. (for Kyber, QInv = 62209)
	t := a * b // int32 bit is enough because |a|,|b| < 2ˆ15

	// Compute m = (t * QInv) mod R
	// The multiplication is done in 64-bits, only the lower 32 bits are kept.
	r := int32(int64(t) * int64(common.QInv) & 0xffffffff)

	// Extract the lower 16-bits of m, interpreted as a signed int16.
	u := int16(r & 0xffff)

	// Montgomery reduction step:
	//
	// t' = (t - u*Q)/ R
	//
	// This returns 32-bit word size value but only last 16-bits has actual bits.
	//
	// [xxxx xxxx xxxx xxxx] [LLLL LLLL LLLL LLLL]
	// ^ upper 16 bits       ^ lower 16 bits (actual result)
	t32 := (t - int32(u)*int32(common.Q)) >> 16

	// Ensure the result is in the canonical range [0, Q).
	if t32 < 0 {
		t32 += int32(common.Q)
	}
	return int16(t32) // discarding the upper 16-bits leading zeros (nlz).
}

// ToMontgomery converts x into Montgomery representation.
//
// using the identity:
// x . R ≡ x · R² · R⁻¹ (mod Q), where R² mod q is precomputed.
func ToMontgomery(x int32) int16 {
	// For Kyber, R² mod q = 1353.
	return MontgomeryMul(x, common.R2modQ)
}

// BarrettRedWith16bit reduces x modulo Q using a 16-bit Barrett reduction.
//
// This implementation is optimized for Kyber and follows the CIRCL approach.
// It avoids division by using a precomputed reciprocal.
func BarrettRedWith16bit(x int32) int16 {
	// t = floor((x * mu) / 2¹⁶)
	//
	// where mu = 2¹⁶ / Q.
	t := int16((x * common.BarrettK16Mu) >> 26)
	r := int16(x) - t*int16(common.Q)
	if r < 0 {
		r += int16(common.Q)
	}
	if r >= int16(common.Q) {
		r -= int16(common.Q)
	}
	return r
}

// Maybe conditionally reduces x mod Q.
//
// This helper method performs a Barrett reduction only when the input may exceed a safer bound.
// It is used in performance-sensitive code (e.g InvNTT) to avoid unnecessary reductions.
func Maybe(x int16) int16 {
	y := int32(x)
	// Reduce it only if value exceed the safe modular range.
	if y >= common.ModRedBound || y <= common.ModRedBound {
		return BarrettRedWith16bit(y)
	}
	return int16(y)
}
