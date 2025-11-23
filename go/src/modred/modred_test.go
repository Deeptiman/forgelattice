package modred

import (
	"crypto/rand"
	"github.com/Deeptiman/ntt-hardware-accelerator/go/src/utils"
	"github.com/stretchr/testify/assert"
	"math/big"
	mRand "math/rand"
	"testing"
)

func TestModRed_computeDilithiumRedConstant(t *testing.T) {
	qInv := computeDilithiumRedConstant()
	assert.Equal(t, qInv, uint32(0xfc7fdfff)) // qInv = 4236238847
}

func TestModRed_MontgomeryEncodeWithDilithium(t *testing.T) {
	r := Dilithium.ToModRed(Dilithium_Q)
	oneEnc := uint32((1 << 32) % uint64(Dilithium_Q))
	assert.Equal(t, uint32(4193792), oneEnc)
	assert.Equal(t, r.MontgomeryMulWithDilithium(oneEnc, oneEnc), oneEnc)

	qm1 := uint32(Dilithium_Q - 1)
	qm1Enc := uint32((uint64(qm1) * (1 << 32)) % uint64(Dilithium_Q))
	prod := r.MontgomeryMulWithDilithium(qm1Enc, qm1Enc)
	assert.Equal(t, r.MontgomeryMulWithDilithium(prod, 1), uint32(1))
}

func TestModRed_MontgomeryMulWithDilithium(t *testing.T) {
	r := Dilithium.ToModRed(Dilithium_Q)
	Q := big.NewInt(int64(Dilithium_Q))

	for i := 0; i < 2000; i++ {
		ai, _ := rand.Int(rand.Reader, Q)
		bi, _ := rand.Int(rand.Reader, Q)
		// test values [a * b]
		a := uint32(ai.Uint64())
		b := uint32(bi.Uint64())

		// Mont Encoding
		am := uint32((uint64(a) * (1 << 32)) % uint64(Dilithium_Q))
		bm := uint32((uint64(b) * (1 << 32)) % uint64(Dilithium_Q))

		// Montgomery mul should be equal to Encoding.
		prod := r.MontgomeryMulWithDilithium(am, bm)
		expected := uint32((uint64((uint64(a)*uint64(b))%uint64(Dilithium_Q)) * (1 << 32)) % uint64(Dilithium_Q))
		assert.Equal(t, expected, prod)

		decoded := r.MontgomeryMulWithDilithium(prod, 1)
		assert.Equal(t, uint32((uint64(a)*uint64(b))%uint64(Dilithium_Q)), decoded)

		decodedA := r.MontgomeryMulWithDilithium(am, 1)
		assert.Equal(t, a%uint32(Dilithium_Q), decodedA)

		decodedB := r.MontgomeryMulWithDilithium(bm, 1)
		assert.Equal(t, b%uint32(Dilithium_Q), decodedB)
	}
}

func TestModRed_KyberMontgomeryConstant(t *testing.T) {
	RmodQ := uint32((uint64(1) << 16) % uint64(Kyber_Q))
	assert.Equal(t, RmodQ, uint32(2285))
	assert.Equal(t, R2modQ, int32(1353))

	r := &ModRed{}
	oneEnc := uint32((uint64(1) << 16) % uint64(Kyber_Q))
	res := r.MontgomeryMulWithKyber(int32(oneEnc), int32(oneEnc))
	assert.Equal(t, int16(oneEnc), res)

	qm1 := int32(Kyber_Q - 1)
	qm1Enc := r.ToMontgomeryWithKyber(qm1)
	prod := r.MontgomeryMulWithKyber(int32(qm1Enc), int32(qm1Enc))
	decoded := r.MontgomeryMulWithKyber(int32(prod), 1)
	assert.Equal(t, decoded, int16(1))
}

func TestModRed_MontgomeryMulWithKyber(t *testing.T) {
	r := &ModRed{}
	Q := big.NewInt(int64(Kyber_Q))
	for i := 0; i < 2000; i++ {
		ai, _ := rand.Int(rand.Reader, Q)
		bi, _ := rand.Int(rand.Reader, Q)
		a := int32(ai.Int64())
		b := int32(bi.Int64())

		am := r.ToMontgomeryWithKyber(a)
		bm := r.ToMontgomeryWithKyber(b)

		prod := r.MontgomeryMulWithKyber(int32(am), int32(bm))
		ab := new(big.Int).Mul(ai, bi)
		expectedEnc := uint32((ab.Uint64() * (uint64(1) << 16)) % uint64(Kyber_Q))
		assert.Equal(t, uint32(prod), expectedEnc)

		decoded := r.MontgomeryMulWithKyber(int32(prod), 1)
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
	for _, tc := range tests {
		m := (tc.x * barrettK16Mu) >> 26
		assert.Equal(t, m, tc.expT)
		r := &ModRed{}
		red := r.KyberBarrettReductionWith16Bit(tc.x)
		assert.Equal(t, red, int16(tc.expected))
	}
}

func canonicalModQSigned(x int32) int32 {
	// bring to canonical in [-q+1, q-1], then [0, q)
	r := int64(x) % int64(Kyber_Q)
	if r < 0 {
		r += int64(Kyber_Q)
	}
	return int32(r)
}

func TestModRed_KyberBarrettRandomSigned(t *testing.T) {
	seed := int64(42)
	rng := mRand.New(mRand.NewSource(seed))

	for i := 0; i < 50000; i++ {
		x := rng.Int31n(1<<17) - int32(1<<16)
		r := &ModRed{}
		red := r.KyberBarrettReductionWith16Bit(x)
		assert.Equal(t, int32(red), canonicalModQSigned(x))
	}
}

func TestModRed_KyberBarrettReduceFull(t *testing.T) {
	Q := Kyber_Q
	r := &ModRed{}
	for x := -1 << 15; x <= 1<<15; x++ {
		y1 := int32(r.KyberBarrettReductionWith16Bit(int32(x)))
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
	y := x % int32(Kyber_Q)
	if y < 0 {
		y += int32(Kyber_Q)
	}
	return int16(y)
}

func TestModRed_KyberToMontgomeryFull(t *testing.T) {
	for x := -(1 << 15); x < 1<<15; x++ {
		r := &ModRed{}
		y := r.ToMontgomeryWithKyber(int32(x))
		y1 := modQ32(int32(y))
		y2 := modQ32(int32(x * 2285))
		if y1 != y2 {
			t.Fatalf("%d:%d:%d", x, y1, y2)
		}
	}
}

func TestModRed_KyberMontgomeryEncodeDecode(t *testing.T) {
	r := &ModRed{}
	for x := -(1 << 15); x <= (1 << 15); x++ {
		// 1) Encode: x --> xR mod Q
		enc := r.MontgomeryMulWithKyber(int32(x), int32(R2modQ))

		// 2) Decode: (xR) * R⁻¹ ≡ x mod Q
		dec := r.MontgomeryMulWithKyber(int32(enc), 1)

		red := modQ32(int32(x))
		assert.Equal(t, dec, red)
	}
}

func TestModRed_BarrettReduceWith32bitRandom(t *testing.T) {
	rng := mRand.New(mRand.NewSource(1337))
	q := uint64(12289)
	m := Generic.ToModRed(q)

	for i := 0; i < 50000; i++ {
		x := rng.Uint32()
		red := m.BarrettReduceWith32bit(uint64(x))
		exp := uint64(x) % q
		assert.Equal(t, exp, red)
	}
}

func TestModRed_BarrettReduceWith64bitRandom(t *testing.T) {
	rng := mRand.New(mRand.NewSource(1337))
	q := uint64(12289)
	m := Generic.ToModRed(q)

	for i := 0; i < 50000; i++ {
		x := rng.Uint64()
		red := m.BarrettReduceWith64bit(x)
		exp := x % q
		assert.Equal(t, exp, red)
	}
}

func TestModRed_HE_EncodeDecode(t *testing.T) {

	q := uint64(HE_Q)
	r := Generic.ToModRed(q)

	for i := 0; i < 10000; i++ {
		x := utils.SecureRNG().Uint64() % q

		enc := r.ToMontgomery(x)
		dec := r.FromMontgomery(enc)

		expected := x % q
		assert.Equal(t, expected, dec)
	}
}

func mulModQ(a, b uint64) uint64 {
	z := new(big.Int).Mul(new(big.Int).SetUint64(a), new(big.Int).SetUint64(b))
	z.Mod(z, new(big.Int).SetUint64(HE_Q))
	return z.Uint64()
}

func TestModRed_MontgomeryMul(t *testing.T) {
	r := Generic.ToModRed(HE_Q)

	for i := 0; i < 10000; i++ {
		a := utils.SecureRNG().Uint64() % HE_Q
		b := utils.SecureRNG().Uint64() % HE_Q

		aM := r.ToMontgomery(a)
		bM := r.ToMontgomery(b)
		prodM := r.MontgomeryMul(aM, bM)
		prod := r.FromMontgomery(prodM)

		assert.Equal(t, mulModQ(a, b), prod)
	}
}
