package homomorphic

import (
	"github.com/Deeptiman/forgekey/go/src/prime"
	"github.com/stretchr/testify/assert"
	"math/big"
	mRand "math/rand"
	"testing"
)

func TestModRed_BarrettReduceWith32bitRandom(t *testing.T) {
	rng := mRand.New(mRand.NewSource(1337))
	q := uint64(12289)
	he := HEInt{Q: q, montConstants: computeMontgomeryConstants(q), barrettConstant: computeBarrettRedConstant(q)}

	for i := 0; i < 50000; i++ {
		x := rng.Uint32()
		red := he.BarrettRedWith32bit(uint64(x))
		exp := uint64(x) % q
		assert.Equal(t, exp, red)
	}
}

func TestModRed_BarrettReduceWith64bitRandom(t *testing.T) {
	rng := mRand.New(mRand.NewSource(1337))
	q := uint64(12289)
	he := HEInt{Q: q, montConstants: computeMontgomeryConstants(q), barrettConstant: computeBarrettRedConstant(q)}

	for i := 0; i < 50000; i++ {
		x := rng.Uint64()
		red := he.BarrettRedWith64bit(x)
		exp := x % q
		assert.Equal(t, exp, red)
	}
}

func TestModRed_HE_EncodeDecode(t *testing.T) {
	q := HEQ
	he := HEInt{Q: q, montConstants: computeMontgomeryConstants(q), barrettConstant: computeBarrettRedConstant(q)}

	for i := 0; i < 10000; i++ {
		x := prime.SecureRNG().Uint64() % q

		enc := he.ToMontgomery(x)
		dec := he.FromMontgomery(enc)

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

	for i := 0; i < 10000; i++ {
		a := prime.SecureRNG().Uint64() % q
		b := prime.SecureRNG().Uint64() % q

		aM := he.ToMontgomery(a)
		bM := he.ToMontgomery(b)
		prodM := he.MontgomeryMul(aM, bM)
		prod := he.FromMontgomery(prodM)

		assert.Equal(t, mulModQ(a, b), prod)
	}
}
