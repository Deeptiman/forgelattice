package dilithium

import (
	"github.com/Deeptiman/forgekey/go/src/prime"
)

var (
	// Q modulus
	Q uint64 = 8380417
	// QInv ...
	QInv uint32 = (^prime.ModInverse32(uint32(Q))) + 1
)

func computeDilithiumRedConstant(q uint64) uint32 {
	return (^prime.ModInverse32(uint32(q))) + 1
}

func MontgomeryMul(a, b int32) int32 {
	t := uint64(a) * uint64(b)                        // maximum upto 64-bits
	mu := uint64(uint32(uint32(t)*QInv) & 0xffffffff) // mu = (t * qInv) & (2³² - 1)
	u := (t + mu*Q) >> 32
	u32 := int32(u)
	if u32 >= int32(Q) {
		u32 -= int32(Q)
	}
	return u32
}
