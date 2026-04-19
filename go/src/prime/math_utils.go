package prime

import (
	"crypto/rand"
	"encoding/binary"
	"math/big"
	"math/bits"
	mRand "math/rand"
)

// FindPrimitiveRoots discovers all primitive N-th roots of unity modulo Q. It iterates over candidates in [2, Q) and
// tests each using the Extended Euclidean Algorithm to verify that it generates the full multiplicative order
// (Q-1)/gcd(N, Q-1) and in returns the count of valid primitive roots.
func FindPrimitiveRoots(q, order uint64, factors []uint64) uint64 {
	Q := new(big.Int).SetUint64(q)
	limit := new(big.Int).Sub(Q, big.NewInt(1))
	for g := uint64(2); ; g++ {
		if new(big.Int).SetUint64(g).Cmp(limit) >= 0 {
			break
		}
		if order <= 512 {
			// test g^order % q == 1
			pow := ModPowWithBarrett(g, order, q)
			if new(big.Int).SetUint64(pow).Cmp(big.NewInt(1)) != 0 {
				continue
			}
		}
		if isPrimitiveRoot(g, q, order, factors) {
			return g
		}
	}
	return 1
}

// isPrimitiveRoot is the internal method which performs the (Q-1)/gcd(N, Q-1) for each factor to find the multiplicative
// order.
func isPrimitiveRoot(g, q, order uint64, factors []uint64) bool {
	for _, f := range factors {
		exp := order / f
		if ModPowWithBarrett(g, exp, q) == 1 {
			return false
		}
	}
	return true
}

func barrettMu(q uint64) uint64 {
	maxBit := ^uint64(0) //2⁶⁴ - 1
	return maxBit / q
}

func BarrettReduce(x, q, mu uint64) uint64 {
	// 1) t = floor(x * Mu64 / 2⁶⁴)
	// Mul64 returns 128-bit product: hi:lo = x * Mu
	hi, _ := bits.Mul64(x, mu) // hi is exactly floor(x*Mu64 / 2⁶⁴)

	// 2) r = x - hi*q
	r := x - hi*q

	// 3) r is now in [0, 2q) (for typical HE standard modulus range)
	// so at most two subtractions normalize into [0, q).
	for r >= q {
		r -= q
	}
	return r
}

func ModMul(a, b, q uint64) uint64 {
	res := a * b % q
	if res < 0 {
		res += q
	}
	return res
}

func ModPow(base, exp, q uint64) uint64 {
	res := uint64(1)
	for exp > 0 { // binary exponentiation
		// Check if last least significant bit is odd-bit.
		if exp&1 == 1 {
			res = ModMul(res, base, q)
		}
		base = ModMul(base, base, q)
		exp >>= 1 // right to left shift to read through least significant bits.
	}
	return res
}

func ModPowWithBarrett(base, exp, q uint64) uint64 {
	mu := barrettMu(q)
	res := uint64(1)
	for exp > 0 { // binary exponentiation
		// Check if last least significant bit is odd-bit.
		if exp&1 == 1 {
			res = BarrettReduce(res*base, q, mu)
		}
		base = BarrettReduce(base*base, q, mu)
		exp >>= 1 // right to left shift to read through least significant bits.
	}
	return res
}

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
