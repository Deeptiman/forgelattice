package utils

import (
	"crypto/rand"
	"encoding/binary"
	"math/big"
	mRand "math/rand"
)

func ModInverse32(q uint32) uint32 {
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

func ModMul(a, b, mod int64) int64 {
	res := a * b % mod
	if res < 0 {
		res += mod
	}
	return res
}

func ModPow(base, exp, mod int64) int64 {
	res := int64(1)
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

func ToInt64(factors []uint64) []int64 {
	factorInt64 := make([]int64, 0, len(factors))
	for _, factor := range factors {
		factorInt64 = append(factorInt64, int64(factor))
	}
	return factorInt64
}

// Abs returns |x|.
func Abs(x *big.Int) *big.Int {
	if x.Sign() < 0 {
		return new(big.Int).Neg(x)
	}
	return new(big.Int).Set(x)
}

func SecureRNG() *mRand.Rand {
	var seedBytes [8]byte
	_, _ = rand.Read(seedBytes[:])
	seed := int64(binary.LittleEndian.Uint64(seedBytes[:]))
	return mRand.New(mRand.NewSource(seed))
}
