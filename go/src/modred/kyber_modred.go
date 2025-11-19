package modred

const (
	Kyber_Q    = 3329
	Kyber_QInv = int32(62209) // qInv = q⁻¹ mod 2¹⁶
	R2modQ     = int32(1353)  // R² mod Q
)

// MontgomeryMulWithKyber ...
//
// Source: https://github.com/cloudflare/circl/blob/main/pke/kyber/internal/common/field.go#L4
func (r *ModRed) MontgomeryMulWithKyber(a, b int32) int16 {
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
	//
	t := a * b // int32 bit is enough because |a|,|b| < 2ˆ15
	// Multiply by Kyber_QInv in 64-bit and takes lower 32-bit
	m := int32(int64(t) * int64(Kyber_QInv) & 0xffffffff)
	// Extract the lower 16-bits of m, interpreted as a signed int16.
	u := int16(m & 0xffff)
	// Montgomery reduction step:
	// t' = (t - u*q)/ 2ˆ16
	// This returns 32-bit word size value but only last 16-bits has actual bits.
	//
	// [xxxx xxxx xxxx xxxx] [LLLL LLLL LLLL LLLL]
	// ^ upper 16 bits       ^ lower 16 bits (actual result)
	t32 := (t - int32(u)*int32(Kyber_Q)) >> 16
	if t32 < 0 {
		t32 += int32(Kyber_Q) // complement t32
	}
	return int16(t32) // discarding the upper 16-bits leading zeros (nlz).
}

// ToMontgomeryWithKyber ...
func (r *ModRed) ToMontgomeryWithKyber(x int32) int16 {
	// R² mod q = 1353 for Kyber.
	return r.MontgomeryMulWithKyber(x, int32(R2modQ))
}
