package reduction

import (
	"crypto/rand"
	"github.com/Deeptiman/forgelattice/crypto/kem/internal/common"
	"github.com/stretchr/testify/assert"
	"math/big"
	mRand "math/rand"
	"testing"
)

func TestMontgomeryConstant(t *testing.T) {
	RmodQ := uint32((uint64(1) << 16) % uint64(common.Q))
	assert.Equal(t, RmodQ, uint32(2285))
	assert.Equal(t, common.R2modQ, int32(1353))

	oneEnc := (1 << 16) * common.Q
	res := MontgomeryMul(int32(oneEnc), int32(oneEnc))
	assert.Equal(t, int16(oneEnc), res)

	qm1 := common.Q - 1
	qm1Enc := ToMontgomery(int32(qm1))
	prod := MontgomeryMul(int32(qm1Enc), int32(qm1Enc))
	decoded := MontgomeryMul(int32(prod), 1)
	assert.Equal(t, decoded, int16(1))
}

func canonicalModQ(x int16) int32 {
	y := int32(x)
	if y < 0 {
		y += int32(common.Q)
	}
	return y
}

func TestMontgomeryMul(t *testing.T) {
	QBig := big.NewInt(int64(common.Q))
	for i := 0; i < 2000; i++ {
		ai, _ := rand.Int(rand.Reader, QBig)
		bi, _ := rand.Int(rand.Reader, QBig)
		a := int32(ai.Int64())
		b := int32(bi.Int64())

		am := ToMontgomery(a)
		bm := ToMontgomery(b)

		prod := MontgomeryMul(int32(am), int32(bm))
		ab := new(big.Int).Mul(ai, bi)
		decoded := MontgomeryMul(int32(prod), 1)
		expected := new(big.Int).Mul(ai, bi).Mod(ab, QBig)
		assert.Equal(t, expected.Int64(), int64(canonicalModQ(decoded)))
	}
}

func canonicalModQSigned(x int32) int32 {
	// bring to canonical in [-q+1, q-1], then [0, q)
	r := int64(x) % int64(common.Q)
	if r < 0 {
		r += int64(common.Q)
	}
	return int32(r)
}

func TestBarrettRandomSigned(t *testing.T) {
	seed := int64(42)
	rng := mRand.New(mRand.NewSource(seed))

	for i := 0; i < 50000; i++ {
		x := rng.Int31n(1<<17) - int32(1<<16)
		red := BarrettRedWith16bit(x)
		assert.Equal(t, int32(red), canonicalModQSigned(x))
	}
}

func TestBarrettReduceFull(t *testing.T) {
	for x := -1 << 15; x <= 1<<15; x++ {
		y1 := int32(BarrettRedWith16bit(int32(x)))
		y2 := int32(x) % int32(common.Q)
		if y2 < 0 {
			y2 += int32(common.Q)
		}
		if y1 != y2 {
			t.Fatalf("%d %d %d", x, y1, y2) // Fail at: y1 = -3329, y2 = 3329
		}
	}
}
