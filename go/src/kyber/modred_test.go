package kyber

import (
	"crypto/rand"
	"github.com/stretchr/testify/assert"
	"math/big"
	mRand "math/rand"
	"testing"
)

func TestKyberMontgomeryConstant(t *testing.T) {
	RmodQ := uint32((uint64(1) << 16) % uint64(Q))
	assert.Equal(t, RmodQ, uint32(2285))
	assert.Equal(t, R2modQ, int32(1353))

	oneEnc := uint32((uint64(1) << 16) % uint64(Q))
	res := MontgomeryMul(int32(oneEnc), int32(oneEnc))
	assert.Equal(t, int16(oneEnc), res)

	qm1 := Q - 1
	qm1Enc := ToMontgomeryWithKyber(int32(qm1))
	prod := MontgomeryMul(int32(qm1Enc), int32(qm1Enc))
	decoded := MontgomeryMul(int32(prod), 1)
	assert.Equal(t, decoded, int16(1))
}

func TestMontgomeryMulWithKyber(t *testing.T) {
	QBig := big.NewInt(int64(Q))
	for i := 0; i < 2000; i++ {
		ai, _ := rand.Int(rand.Reader, QBig)
		bi, _ := rand.Int(rand.Reader, QBig)
		a := int32(ai.Int64())
		b := int32(bi.Int64())

		am := ToMontgomeryWithKyber(a)
		bm := ToMontgomeryWithKyber(b)

		prod := MontgomeryMul(int32(am), int32(bm))
		ab := new(big.Int).Mul(ai, bi)
		expectedEnc := uint32((ab.Uint64() * (uint64(1) << 16)) % uint64(Q))
		assert.Equal(t, uint32(prod), expectedEnc)

		decoded := MontgomeryMul(int32(prod), 1)
		assert.Equal(t, int(decoded), int(new(big.Int).Mul(ai, bi).Mod(ab, QBig).Int64()))
	}
}

func TestKyberBarretTestVector(t *testing.T) {
	type testCases struct {
		x        int32
		expected int32
		expT     int32
	}
	tests := []testCases{
		{0, 0, 0},
		{1, 1, 0},
		{100, 100, 0},
		{2602, 2602, 0},
		{3328, 3328, 0},
		{3329, 0, 1},
		{3330, 1, 1},
		{65535, 2284, 19},
		{65536, 2285, 19},
		{-1, 3328, -1},
		{-3329, 0, -2},
		{-65536, 1044, -20},
	}
	for _, tc := range tests {
		m := (tc.x * BarrettK16Mu) >> 26
		assert.Equal(t, m, tc.expT)
		red := BarrettRedWith16bit(tc.x)
		assert.Equal(t, red, int16(tc.expected))
	}
}

func canonicalModQSigned(x int32) int32 {
	// bring to canonical in [-q+1, q-1], then [0, q)
	r := int64(x) % int64(Q)
	if r < 0 {
		r += int64(Q)
	}
	return int32(r)
}

func TestKyberBarrettRandomSigned(t *testing.T) {
	seed := int64(42)
	rng := mRand.New(mRand.NewSource(seed))

	for i := 0; i < 50000; i++ {
		x := rng.Int31n(1<<17) - int32(1<<16)
		red := BarrettRedWith16bit(x)
		assert.Equal(t, int32(red), canonicalModQSigned(x))
	}
}

func TestKyberBarrettReduceFull(t *testing.T) {
	for x := -1 << 15; x <= 1<<15; x++ {
		y1 := int32(BarrettRedWith16bit(int32(x)))
		y2 := int32(x) % int32(Q)
		if y2 < 0 {
			y2 += int32(Q)
		}
		if y1 != y2 {
			t.Fatalf("%d %d %d", x, y1, y2) // Fail at: y1 = -3329, y2 = 3329
		}
	}
}

func modQ32(x int32) int16 {
	y := x % int32(Q)
	if y < 0 {
		y += int32(Q)
	}
	return int16(y)
}

func TestKyberToMontgomeryFull(t *testing.T) {
	for x := -(1 << 15); x < 1<<15; x++ {
		y := ToMontgomeryWithKyber(int32(x))
		y1 := modQ32(int32(y))
		y2 := modQ32(int32(x * 2285))
		if y1 != y2 {
			t.Fatalf("%d:%d:%d", x, y1, y2)
		}
	}
}

func TestKyberMontgomeryEncodeDecode(t *testing.T) {
	for x := -(1 << 15); x <= (1 << 15); x++ {
		// 1) Encode: x --> xR mod Q
		enc := MontgomeryMul(int32(x), R2modQ)

		// 2) Decode: (xR) * R⁻¹ ≡ x mod Q
		dec := MontgomeryMul(int32(enc), 1)

		red := modQ32(int32(x))
		assert.Equal(t, dec, red)
	}
}

func TestPrecomputeTwiddleFactor(t *testing.T) {
	root := FindPrimitiveRoot()
	assert.Equal(t, 17, root)
	assert.Equal(t, Zetas, PrecomputeKyberZetas())
}

var Zetas = [128]int16{
	2285, 2571, 2970, 1812, 1493, 1422, 287, 202, 3158, 622, 1577, 182,
	962, 2127, 1855, 1468, 573, 2004, 264, 383, 2500, 1458, 1727, 3199,
	2648, 1017, 732, 608, 1787, 411, 3124, 1758, 1223, 652, 2777, 1015,
	2036, 1491, 3047, 1785, 516, 3321, 3009, 2663, 1711, 2167, 126,
	1469, 2476, 3239, 3058, 830, 107, 1908, 3082, 2378, 2931, 961, 1821,
	2604, 448, 2264, 677, 2054, 2226, 430, 555, 843, 2078, 871, 1550,
	105, 422, 587, 177, 3094, 3038, 2869, 1574, 1653, 3083, 778, 1159,
	3182, 2552, 1483, 2727, 1119, 1739, 644, 2457, 349, 418, 329, 3173,
	3254, 817, 1097, 603, 610, 1322, 2044, 1864, 384, 2114, 3193, 1218,
	1994, 2455, 220, 2142, 1670, 2144, 1799, 2051, 794, 1819, 2475,
	2459, 478, 3221, 3021, 996, 991, 958, 1869, 1522, 1628,
}
