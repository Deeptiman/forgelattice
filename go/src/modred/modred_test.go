package modred

import (
	"crypto/rand"
	"github.com/Deeptiman/forgekey/go/src/utils"
	"github.com/stretchr/testify/assert"
	"math/big"
	mRand "math/rand"
	"testing"
)

func TestModRed_computeDilithiumRedConstant(t *testing.T) {
	qInv := computeDilithiumRedConstant(DilithiumQ)
	assert.Equal(t, qInv, uint32(0xfc7fdfff)) // qInv = 4236238847
}

func TestModRed_MontgomeryEncodeWithDilithium(t *testing.T) {
	oneEnc := uint32((1 << 32) % uint64(DilithiumQ))
	assert.Equal(t, uint32(4193792), oneEnc)
	var d DilithiumInt
	m := NewModDirective[int32, int32, DilithiumInt](d)
	assert.Equal(t, m.Red.MontgomeryMul(int32(oneEnc), int32(oneEnc)), int32(oneEnc))

	qm1 := uint32(DilithiumQ - 1)
	qm1Enc := uint32((uint64(qm1) * (1 << 32)) % DilithiumQ)
	prod := m.Red.MontgomeryMul(int32(qm1Enc), int32(qm1Enc))
	assert.Equal(t, m.Red.MontgomeryMul(prod, 1), int32(1))
}

func TestModRed_MontgomeryMulWithDilithium(t *testing.T) {
	Q := big.NewInt(int64(DilithiumQ))
	var d DilithiumInt
	m := NewModDirective[int32, int32, DilithiumInt](d)

	for i := 0; i < 2000; i++ {
		ai, err := rand.Int(rand.Reader, Q)
		assert.NoError(t, err)
		bi, err := rand.Int(rand.Reader, Q)
		assert.NoError(t, err)
		// test values [a * b]
		a := uint32(ai.Uint64())
		b := uint32(bi.Uint64())

		// Mont Encoding
		am := uint32((uint64(a) * (1 << 32)) % DilithiumQ)
		bm := uint32((uint64(b) * (1 << 32)) % DilithiumQ)

		// Montgomery mul should be equal to Encoding.
		prod := m.Red.MontgomeryMul(int32(am), int32(bm))
		expected := uint32((uint64((uint64(a)*uint64(b))%DilithiumQ) * (1 << 32)) % DilithiumQ)
		assert.Equal(t, int32(expected), prod)

		decoded := m.Red.MontgomeryMul(prod, 1)
		assert.Equal(t, int32((uint64(a)*uint64(b))%DilithiumQ), decoded)

		decodedA := m.Red.MontgomeryMul(int32(am), 1)
		assert.Equal(t, int32(a%uint32(DilithiumQ)), decodedA)

		decodedB := m.Red.MontgomeryMul(int32(bm), 1)
		assert.Equal(t, int32(b%uint32(DilithiumQ)), decodedB)
	}
}

func TestModRed_KyberMontgomeryConstant(t *testing.T) {
	RmodQ := uint32((uint64(1) << 16) % uint64(KyberQ))
	assert.Equal(t, RmodQ, uint32(2285))
	assert.Equal(t, KyberR2modQ, int32(1353))

	var k KyberInt
	m := NewModDirective[int32, int16, KyberInt](k)
	oneEnc := uint32((uint64(1) << 16) % uint64(KyberQ))
	res := m.Red.MontgomeryMul(int32(oneEnc), int32(oneEnc))
	assert.Equal(t, int16(oneEnc), res)

	qm1 := KyberQ - 1
	qm1Enc := k.ToMontgomeryWithKyber(qm1)
	prod := m.Red.MontgomeryMul(int32(qm1Enc), int32(qm1Enc))
	decoded := m.Red.MontgomeryMul(int32(prod), 1)
	assert.Equal(t, decoded, int16(1))
}

func TestModRed_MontgomeryMulWithKyber(t *testing.T) {
	var k KyberInt
	m := NewModDirective[int32, int16, KyberInt](k)
	Q := big.NewInt(int64(KyberQ))
	for i := 0; i < 2000; i++ {
		ai, _ := rand.Int(rand.Reader, Q)
		bi, _ := rand.Int(rand.Reader, Q)
		a := int32(ai.Int64())
		b := int32(bi.Int64())

		am := k.ToMontgomeryWithKyber(a)
		bm := k.ToMontgomeryWithKyber(b)

		prod := m.Red.MontgomeryMul(int32(am), int32(bm))
		ab := new(big.Int).Mul(ai, bi)
		expectedEnc := uint32((ab.Uint64() * (uint64(1) << 16)) % uint64(KyberQ))
		assert.Equal(t, uint32(prod), expectedEnc)

		decoded := m.Red.MontgomeryMul(int32(prod), 1)
		assert.Equal(t, int(decoded), int(new(big.Int).Mul(ai, bi).Mod(ab, Q).Int64()))
	}
}

func TestModRed_KyberBarretTestVector(t *testing.T) {
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
	var k KyberInt
	for _, tc := range tests {
		m := (tc.x * KyberBarrettK16Mu) >> 26
		assert.Equal(t, m, tc.expT)
		red := k.BarrettRedWith16bit(tc.x)
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

func TestModRed_KyberBarrettRandomSigned(t *testing.T) {
	seed := int64(42)
	rng := mRand.New(mRand.NewSource(seed))

	var k KyberInt
	for i := 0; i < 50000; i++ {
		x := rng.Int31n(1<<17) - int32(1<<16)
		red := k.BarrettRedWith16bit(x)
		assert.Equal(t, int32(red), canonicalModQSigned(x))
	}
}

func TestModRed_KyberBarrettReduceFull(t *testing.T) {
	Q := KyberQ
	var k KyberInt
	for x := -1 << 15; x <= 1<<15; x++ {
		y1 := int32(k.BarrettRedWith16bit(int32(x)))
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

func TestModRed_KyberToMontgomeryFull(t *testing.T) {
	var k KyberInt
	for x := -(1 << 15); x < 1<<15; x++ {
		y := k.ToMontgomeryWithKyber(int32(x))
		y1 := modQ32(int32(y))
		y2 := modQ32(int32(x * 2285))
		if y1 != y2 {
			t.Fatalf("%d:%d:%d", x, y1, y2)
		}
	}
}

func TestModRed_KyberMontgomeryEncodeDecode(t *testing.T) {
	var k KyberInt
	m := NewModDirective[int32, int16, KyberInt](k)
	for x := -(1 << 15); x <= (1 << 15); x++ {
		// 1) Encode: x --> xR mod Q
		enc := m.Red.MontgomeryMul(int32(x), KyberR2modQ)

		// 2) Decode: (xR) * R⁻¹ ≡ x mod Q
		dec := m.Red.MontgomeryMul(int32(enc), 1)

		red := modQ32(int32(x))
		assert.Equal(t, dec, red)
	}
}

func TestModRed_BarrettReduceWith32bitRandom(t *testing.T) {
	rng := mRand.New(mRand.NewSource(1337))
	q := uint64(12289)
	he := HEInt{Q: q, montConstants: computeMontgomeryConstants(q), barrettConstant: computeBarrettRedConstant(q)}
	m := NewModDirective[uint64, uint64, HEInt](he)

	for i := 0; i < 50000; i++ {
		x := rng.Uint32()
		red := m.Red.BarrettRedWith32bit(uint64(x))
		exp := uint64(x) % q
		assert.Equal(t, exp, red)
	}
}

func TestModRed_BarrettReduceWith64bitRandom(t *testing.T) {
	rng := mRand.New(mRand.NewSource(1337))
	q := uint64(12289)
	he := HEInt{Q: q, montConstants: computeMontgomeryConstants(q), barrettConstant: computeBarrettRedConstant(q)}
	m := NewModDirective[uint64, uint64, HEInt](he)

	for i := 0; i < 50000; i++ {
		x := rng.Uint64()
		red := m.Red.BarrettRedWith64bit(x)
		exp := x % q
		assert.Equal(t, exp, red)
	}
}

func TestModRed_HE_EncodeDecode(t *testing.T) {
	q := HEQ
	he := HEInt{Q: q, montConstants: computeMontgomeryConstants(q), barrettConstant: computeBarrettRedConstant(q)}
	m := NewModDirective[uint64, uint64, HEInt](he)

	for i := 0; i < 10000; i++ {
		x := utils.SecureRNG().Uint64() % q

		enc := m.Red.ToMontgomery(x)
		dec := m.Red.FromMontgomery(enc)

		expected := x % q
		assert.Equal(t, expected, dec)
	}
}

func mulModQ(a, b uint64) uint64 {
	z := new(big.Int).Mul(new(big.Int).SetUint64(a), new(big.Int).SetUint64(b))
	z.Mod(z, new(big.Int).SetUint64(HEQ))
	return z.Uint64()
}

func TestModRed_MontgomeryMul(t *testing.T) {
	q := HEQ
	he := HEInt{Q: q, montConstants: computeMontgomeryConstants(q), barrettConstant: computeBarrettRedConstant(q)}
	m := NewModDirective[uint64, uint64, HEInt](he)

	for i := 0; i < 10000; i++ {
		a := utils.SecureRNG().Uint64() % q
		b := utils.SecureRNG().Uint64() % q

		aM := m.Red.ToMontgomery(a)
		bM := m.Red.ToMontgomery(b)
		prodM := m.Red.MontgomeryMul(aM, bM)
		prod := m.Red.FromMontgomery(prodM)

		assert.Equal(t, mulModQ(a, b), prod)
	}
}
