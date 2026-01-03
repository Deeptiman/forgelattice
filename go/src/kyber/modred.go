package kyber

func montReduce(x int32) int16 {
	//return int16(uint32(x-int32(int16(x*62209))*int32(Q)) >> 16)
	return int16(x - int32(int16(x*62209))*int32(Q)>>16)
}

// MontgomeryMul ...
//
// Source: https://github.com/cloudflare/circl/blob/main/pke/kyber/internal/common/field.go#L4
func MontgomeryMul(a, b int32) int16 {
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
	// Multiply by QInv in 64-bit and takes lower 32-bit
	r := int32(int64(t) * int64(QInv) & 0xffffffff)
	// Extract the lower 16-bits of m, interpreted as a signed int16.
	u := int16(r & 0xffff)
	// Montgomery reduction step:
	// t' = (t - u*q)/ 2ˆ16
	// This returns 32-bit word size value but only last 16-bits has actual bits.
	//
	// [xxxx xxxx xxxx xxxx] [LLLL LLLL LLLL LLLL]
	// ^ upper 16 bits       ^ lower 16 bits (actual result)
	t32 := (t - int32(u)*int32(Q)) >> 16
	if t32 < 0 {
		t32 += int32(Q) // complement t32
	}
	return int16(t32) // discarding the upper 16-bits leading zeros (nlz).
}

// ToMontgomeryWithKyber ...
func ToMontgomeryWithKyber(x int32) int16 {
	// R² mod q = 1353 for Kyber.
	return MontgomeryMul(x, R2modQ)
}

// BarrettRedWith16bit ...
//
// Source: CIRCL repo computes Kyber barrett reduction with 16-bits register.
func BarrettRedWith16bit(x int32) int16 {
	// t = floor( (x * mu16) / 2¹⁶)
	t := int16((x * BarrettK16Mu) >> 26)
	r := int16(x) - t*int16(Q)
	if r < 0 {
		r += int16(Q)
	}
	if r >= int16(Q) {
		r -= int16(Q)
	}
	return r
}

func maybeReduce(x int16) int16 {
	y := int32(x)
	if y >= ModRedBound || y <= ModRedBound {
		return BarrettRedWith16bit(y)
	}
	return int16(y)
}
