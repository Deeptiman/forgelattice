package modred

import "github.com/Deeptiman/forgekey/go/src/utils"

func computeDilithiumRedConstant(q uint64) uint32 {
	return (^utils.ModInverse32(uint32(q))) + 1
}

func (d DilithiumInt) MontgomeryMul(a, b int32) int32 {
	t := uint64(a) * uint64(b)                                 // maximum upto 64-bits
	mu := uint64(uint32(uint32(t)*DilithiumQInv) & 0xffffffff) // mu = (t * qInv) & (2³² - 1)
	u := (t + mu*DilithiumQ) >> 32
	u32 := int32(u)
	if u32 >= int32(DilithiumQ) {
		u32 -= int32(DilithiumQ)
	}
	return u32
}

func (d DilithiumInt) ToMontgomeryWithDilithium(a, b int32) int32 {
	return d.MontgomeryMul(a, b)
}
