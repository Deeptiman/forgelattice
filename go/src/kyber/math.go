package kyber

func ModMul(a, b, mod int16) int16 {
	res := a * b % mod
	if res < 0 {
		res += mod
	}
	return res
}

func ModPow(base, exp, mod int16) int16 {
	res := int16(1)
	for exp > 0 { // binary exponentiation
		// Check if last least significant bit is odd-bit.
		if exp&1 == 1 {
			res = ModMul(res, base, mod)
		}
		base = ModMul(base, base, mod)
		exp >>= 1 // right to left shift to read through least significant bits.
	}
	return res
}
