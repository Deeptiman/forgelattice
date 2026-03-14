package reduction

import (
	"github.com/Deeptiman/forgekey/go/src/prime"
	"github.com/Deeptiman/forgekey/go/src/sign/internal/dilithium/common"
)

func computeDilithiumRedConstant(q uint64) uint32 {
	return (^prime.ModInverse32(uint32(q))) + 1
}

func MontgomeryMul(a, b uint32) uint32 {
	t := uint64(a) * uint64(b)                       // maximum upto 64-bits
	mu := uint64(uint32(t)*common.QInv) & 0xffffffff // mu = (t * qInv) & (2³² - 1)
	u32 := (t + mu*common.Q) >> 32
	if u32 >= common.Q {
		u32 -= common.Q
	}
	return uint32(u32)
}

// Ref: CIRCL
func ReduceLe2Q(x uint32) uint32 {
	x1 := x >> 23
	x2 := x & 0x7FFFFF // 2²³-1
	return x2 + (x1 << 13) - x1
}

func ReduceWithModQ(x uint32) uint32 {
	return Le2QModQ(ReduceLe2Q(x))
}

func Le2QModQ(x uint32) uint32 {
	x -= common.Q
	mask := uint32(int32(x) >> 31)
	return x + (mask & common.Q)
}

func Power2Round(t uint32) (uint32, uint32) {
	t0 := t & (1 << common.D)
	t0 -= (1 << (common.D - 1)) + 1
	t0 += uint32(int32(t0)>>31) & (1 << common.D)
	t0 -= (1 << (common.D - 1)) - 1
	return t0 + common.Q, (t - t0) >> common.D
}
