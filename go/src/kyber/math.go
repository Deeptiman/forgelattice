package kyber

func BitReverse(x int) int {
	var r int
	for i := 0; i < 7; i++ {
		r = (r << 1) | (x & 1)
		x >>= 1
	}
	return r
}

func ModMul(a, b, mod int) int {
	res := a * b % mod
	if res < 0 {
		res += mod
	}
	return res
}

func ModPow(base, exp, mod int) int {
	res := 1
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
