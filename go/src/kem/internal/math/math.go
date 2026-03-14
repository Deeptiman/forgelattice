package math

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

func ModInverse(a, q int32) int32 {
	var t0, t1 int32 = 0, 1
	var r0, r1 int32 = q, a

	for r1 != 0 {
		quotient := r0 / r1
		r0, r1 = r1, r0-quotient*r1
		t0, t1 = t1, t0-quotient*t1
	}

	if t0 < 0 {
		t0 += q
	}
	return t0
}
