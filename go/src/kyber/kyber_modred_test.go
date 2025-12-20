package kyber

import (
	"crypto/rand"
	"github.com/stretchr/testify/assert"
	"math/big"
	mRand "math/rand"
	"testing"
)

func TestKyberMontgomeryConstant(t *testing.T) {
	RmodQ := uint32((uint64(1) << 16) % uint64(KyberQ))
	assert.Equal(t, RmodQ, uint32(2285))
	assert.Equal(t, KyberR2modQ, int32(1353))

	oneEnc := uint32((uint64(1) << 16) % uint64(KyberQ))
	res := MontgomeryMul(int32(oneEnc), int32(oneEnc))
	assert.Equal(t, int16(oneEnc), res)

	qm1 := KyberQ - 1
	qm1Enc := ToMontgomeryWithKyber(qm1)
	prod := MontgomeryMul(int32(qm1Enc), int32(qm1Enc))
	decoded := MontgomeryMul(int32(prod), 1)
	assert.Equal(t, decoded, int16(1))
}

func TestMontgomeryMulWithKyber(t *testing.T) {
	Q := big.NewInt(int64(KyberQ))
	for i := 0; i < 2000; i++ {
		ai, _ := rand.Int(rand.Reader, Q)
		bi, _ := rand.Int(rand.Reader, Q)
		a := int32(ai.Int64())
		b := int32(bi.Int64())

		am := ToMontgomeryWithKyber(a)
		bm := ToMontgomeryWithKyber(b)

		prod := MontgomeryMul(int32(am), int32(bm))
		ab := new(big.Int).Mul(ai, bi)
		expectedEnc := uint32((ab.Uint64() * (uint64(1) << 16)) % uint64(KyberQ))
		assert.Equal(t, uint32(prod), expectedEnc)

		decoded := MontgomeryMul(int32(prod), 1)
		assert.Equal(t, int(decoded), int(new(big.Int).Mul(ai, bi).Mod(ab, Q).Int64()))
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
		m := (tc.x * KyberBarrettK16Mu) >> 26
		assert.Equal(t, m, tc.expT)
		red := BarrettRedWith16bit(tc.x)
		assert.Equal(t, red, int16(tc.expected))
	}
}

func canonicalModQSigned(x int32) int32 {
	// bring to canonical in [-q+1, q-1], then [0, q)
	r := int64(x) % int64(KyberQ)
	if r < 0 {
		r += int64(KyberQ)
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
	Q := KyberQ
	for x := -1 << 15; x <= 1<<15; x++ {
		y1 := int32(BarrettRedWith16bit(int32(x)))
		y2 := int32(x) % Q
		if y2 < 0 {
			y2 += Q
		}
		if y1 != y2 {
			t.Fatalf("%d %d %d", x, y1, y2) // Fail at: y1 = -3329, y2 = 3329
		}
	}
}

func modQ32(x int32) int16 {
	y := x % KyberQ
	if y < 0 {
		y += KyberQ
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
		enc := MontgomeryMul(int32(x), KyberR2modQ)

		// 2) Decode: (xR) * R⁻¹ ≡ x mod Q
		dec := MontgomeryMul(int32(enc), 1)

		red := modQ32(int32(x))
		assert.Equal(t, dec, red)
	}
}
