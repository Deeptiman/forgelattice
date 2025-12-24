package dilithium

import (
	"crypto/rand"
	"github.com/stretchr/testify/assert"
	"math/big"
	"testing"
)

func TestModRed_computeDilithiumRedConstant(t *testing.T) {
	qInv := computeDilithiumRedConstant(Q)
	assert.Equal(t, qInv, uint32(0xfc7fdfff)) // qInv = 4236238847
}

func TestModRed_MontgomeryEncodeWithDilithium(t *testing.T) {
	oneEnc := uint32((1 << 32) % uint64(Q))
	assert.Equal(t, uint32(4193792), oneEnc)
	assert.Equal(t, MontgomeryMul(int32(oneEnc), int32(oneEnc)), int32(oneEnc))

	qm1 := uint32(Q - 1)
	qm1Enc := uint32((uint64(qm1) * (1 << 32)) % Q)
	prod := MontgomeryMul(int32(qm1Enc), int32(qm1Enc))
	assert.Equal(t, MontgomeryMul(prod, 1), int32(1))
}

func TestModRed_MontgomeryMulWithDilithium(t *testing.T) {
	QBig := big.NewInt(int64(Q))

	for i := 0; i < 2000; i++ {
		ai, err := rand.Int(rand.Reader, QBig)
		assert.NoError(t, err)
		bi, err := rand.Int(rand.Reader, QBig)
		assert.NoError(t, err)
		// test values [a * b]
		a := uint32(ai.Uint64())
		b := uint32(bi.Uint64())

		// Mont Encoding
		am := uint32((uint64(a) * (1 << 32)) % Q)
		bm := uint32((uint64(b) * (1 << 32)) % Q)

		// Montgomery mul should be equal to Encoding.
		prod := MontgomeryMul(int32(am), int32(bm))
		expected := uint32((uint64((uint64(a)*uint64(b))%Q) * (1 << 32)) % Q)
		assert.Equal(t, int32(expected), prod)

		decoded := MontgomeryMul(prod, 1)
		assert.Equal(t, int32((uint64(a)*uint64(b))%Q), decoded)

		decodedA := MontgomeryMul(int32(am), 1)
		assert.Equal(t, int32(a%uint32(Q)), decodedA)

		decodedB := MontgomeryMul(int32(bm), 1)
		assert.Equal(t, int32(b%uint32(Q)), decodedB)
	}
}
