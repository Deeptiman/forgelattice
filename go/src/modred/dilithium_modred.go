package modred

const (
	Dilithium_Q        = 8380417
	Dilithium_R uint64 = 1 << 32
)

func computeDilithiumRedConstant() uint32 {
	// RmodQ := uint32(Dilithium_R % uint64(Dilithium_Q))
	qModInv := modInverse32(uint32(Dilithium_Q))
	return (^qModInv) + 1
}

func modInverse32(q uint32) uint32 {
	var t0, t1 int64 = 0, 1
	var r0, r1 int64 = 1 << 32, int64(q)
	for r1 != 0 {
		q1 := r0 / r1
		r0, r1 = r1, r0-q1*r1
		t0, t1 = t1, t0-q1*t1
	}
	if t0 < 0 {
		t0 += 1 << 32
	}
	return uint32(t0)
}

func (r *ModRed) MontgomeryMulWithDilithium(a, b uint32) uint32 {
	t := uint64(a) * uint64(b)                                    // maximum upto 64-bits
	mu := uint64(uint32(uint32(t)*r.Dilithium_QInv) & 0xffffffff) // mu = (t * qInv) & (2³² - 1)
	u := (t + mu*Dilithium_Q) >> 32
	u32 := uint32(u)
	if u32 >= uint32(Dilithium_Q) {
		u32 -= uint32(Dilithium_Q)
	}
	return u32
}
