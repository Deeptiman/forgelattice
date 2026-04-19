package reduction

import (
	"crypto/rand"
	"fmt"
	"github.com/Deeptiman/forgekey/go/src/sign/dilithium/internal/common"
	"github.com/stretchr/testify/assert"
	"math/big"
	"testing"
)

func TestModRed_computeDilithiumRedConstant(t *testing.T) {
	qInv := computeDilithiumRedConstant(common.Q)
	assert.Equal(t, qInv, uint32(0xfc7fdfff)) // qInv = 4236238847
}

func TestModRed_MontgomeryEncode(t *testing.T) {
	oneEnc := uint32((1 << 32) % uint64(common.Q))
	assert.Equal(t, uint32(4193792), oneEnc)
	assert.Equal(t, MontgomeryMul(oneEnc, oneEnc), oneEnc)

	qm1 := uint32(common.Q - 1)
	qm1Enc := uint32((uint64(qm1) * (1 << 32)) % common.Q)
	prod := MontgomeryMul(qm1Enc, qm1Enc)
	assert.Equal(t, MontgomeryMul(prod, 1), uint32(1))
}

func TestModRed_MontgomeryMul(t *testing.T) {
	for i := 0; i < 200; i++ {
		t.Run(fmt.Sprintf("Montgomery(DSA)-Test=%d", i), func(t *testing.T) {
			t.Parallel()
			QBig := big.NewInt(int64(common.Q))
			ai, err := rand.Int(rand.Reader, QBig)
			assert.NoError(t, err)
			bi, err := rand.Int(rand.Reader, QBig)
			assert.NoError(t, err)
			// test values [a * b]
			a := uint32(ai.Uint64())
			b := uint32(bi.Uint64())

			// Mont Encoding
			am := uint32((uint64(a) * (1 << 32)) % common.Q)
			bm := uint32((uint64(b) * (1 << 32)) % common.Q)

			// Montgomery mul should be equal to Encoding.
			prod := MontgomeryMul(am, bm)
			x := ((uint64(a) * uint64(b)) % common.Q) * (1 << 32)
			expected := uint32(x % common.Q)
			assert.Equal(t, expected, prod)

			decoded := MontgomeryMul(prod, 1)
			assert.Equal(t, uint32((uint64(a)*uint64(b))%common.Q), decoded)

			decodedA := MontgomeryMul(am, 1)
			assert.Equal(t, a%uint32(common.Q), decodedA)

			decodedB := MontgomeryMul(bm, 1)
			assert.Equal(t, b%uint32(common.Q), decodedB)
		})
	}
}
