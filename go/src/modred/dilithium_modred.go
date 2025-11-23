package modred

import "github.com/Deeptiman/forgekey/go/src/utils"

func computeDilithiumRedConstant(q uint64) uint32 {
	qModInv := utils.ModInverse32(uint32(q))
	return (^qModInv) + 1
}

func (m *ModRed) MontgomeryMulWithDilithium(a, b uint32) uint32 {
	t := uint64(a) * uint64(b)                                   // maximum upto 64-bits
	mu := uint64(uint32(uint32(t)*m.DilithiumQInv) & 0xffffffff) // mu = (t * qInv) & (2³² - 1)
	u := (t + mu*m.DilithiumQ) >> 32
	u32 := uint32(u)
	if u32 >= uint32(m.DilithiumQ) {
		u32 -= uint32(m.DilithiumQ)
	}
	return u32
}
