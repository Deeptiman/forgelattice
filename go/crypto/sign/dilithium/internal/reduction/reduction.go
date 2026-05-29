package reduction

import (
	"github.com/Deeptiman/forgelattice/go/crypto/sign/dilithium/internal/common"
	"github.com/Deeptiman/forgelattice/go/crypto/sign/dilithium/internal/mathutils"
)

func computeDilithiumRedConstant(q uint64) uint32 {
	return (^mathutils.ModInverse32(uint32(q))) + 1
}

func MontgomeryMul(a, b uint32) uint32 {
	// Qinv = 4236238847 = -(q⁻¹) mod 2³²
	x := uint64(a) * uint64(b) // maximum upto 64-bits
	m := uint64(uint32(x)*common.QInv) & 0xffffffff
	return uint32((x + m*uint64(common.Q)) >> 32)
}

func Le2Q(x uint64) uint32 {
	m := uint64(uint32(x)*common.QInv) & 0xffffffff
	return uint32((x + m*uint64(common.Q)) >> 32)
}

func Le2QUsingCIRCL(x uint32) uint32 {
	x1 := x >> 23
	x2 := x & 0x7FFFFF // 2²³-1
	return x2 + (x1 << 13) - x1
}

func Le2QModQ(x uint32) uint32 {
	x -= common.Q
	mask := uint32(int32(x) >> 31)
	return x + (mask & common.Q)
}

func ReduceWithModQ(x uint32) uint32 {
	return Le2QModQ(Le2QUsingCIRCL(x))
}

func Power2Round(t uint32) (uint32, uint32) {
	t0 := t & ((1 << common.D) - 1)
	t0 -= (1 << (common.D - 1)) + 1
	t0 += uint32(int32(t0)>>31) & (1 << common.D)
	t0 -= (1 << (common.D - 1)) - 1
	return t0 + common.Q, (t - t0) >> common.D
}
