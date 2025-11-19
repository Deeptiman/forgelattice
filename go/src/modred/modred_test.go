package modred

import (
	"crypto/rand"
	"github.com/stretchr/testify/assert"
	"math/big"
	"testing"
)

func TestModRed_computeDilithiumRedConstant(t *testing.T) {
	qInv := computeDilithiumRedConstant()
	assert.Equal(t, qInv, uint32(0xfc7fdfff)) // qInv = 4236238847
}

func TestModRed_MontgomeryEncodeWithDilithium(t *testing.T) {
	r := &ModRed{Dilithium_QInv: computeDilithiumRedConstant()}
	oneEnc := uint32((1 << 32) % uint64(Dilithium_Q))
	assert.Equal(t, uint32(4193792), oneEnc)
	assert.Equal(t, r.MontgomeryMulWithDilithium(oneEnc, oneEnc), oneEnc)

	qm1 := uint32(Dilithium_Q - 1)
	qm1Enc := uint32((uint64(qm1) * (1 << 32)) % uint64(Dilithium_Q))
	prod := r.MontgomeryMulWithDilithium(qm1Enc, qm1Enc)
	assert.Equal(t, r.MontgomeryMulWithDilithium(prod, 1), uint32(1))
}

func TestModRed_MontgomeryMulWithDilithium(t *testing.T) {
	r := &ModRed{Dilithium_QInv: computeDilithiumRedConstant()}
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
	assert.Equal(t, R2modQ, uint32(1353))

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
