package modred

// MontgomeryMulWithKyber ...
//
// Source: https://github.com/cloudflare/circl/blob/main/pke/kyber/internal/common/field.go#L4
func (m *ModRed) MontgomeryMulWithKyber(a, b int32) int16 {
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
	// Multiply by KyberQInv in 64-bit and takes lower 32-bit
	r := int32(int64(t) * int64(m.KyberQInv) & 0xffffffff)
	// Extract the lower 16-bits of m, interpreted as a signed int16.
	u := int16(r & 0xffff)
	// Montgomery reduction step:
	// t' = (t - u*q)/ 2ˆ16
	// This returns 32-bit word size value but only last 16-bits has actual bits.
	//
	// [xxxx xxxx xxxx xxxx] [LLLL LLLL LLLL LLLL]
	// ^ upper 16 bits       ^ lower 16 bits (actual result)
	t32 := (t - int32(u)*m.KyberQ) >> 16
	if t32 < 0 {
		t32 += m.KyberQ // complement t32
	}
	return int16(t32) // discarding the upper 16-bits leading zeros (nlz).
}

// ToMontgomeryWithKyber ...
func (m *ModRed) ToMontgomeryWithKyber(x int32) int16 {
	// R² mod q = 1353 for Kyber.
	return m.MontgomeryMulWithKyber(x, m.KyberR2modQ)
}

// KyberBarrettReductionWith16Bit ...
//
// Source: CIRCL repo computes Kyber barrett reduction with 16-bits register.
func (m *ModRed) KyberBarrettReductionWith16Bit(x int32) int16 {
	// t = floor( (x * mu16) / 2¹⁶)
	t := int16((x * m.KyberBarrettK16Mu) >> 26)
	r := int16(x) - t*int16(m.KyberQ)
	if r < 0 {
		r += int16(m.KyberQ)
	}
	if r >= int16(m.KyberQ) {
		r -= int16(m.KyberQ)
	}
	return r
}
