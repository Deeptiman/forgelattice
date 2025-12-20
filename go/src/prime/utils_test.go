package prime

import (
	"fmt"
	"github.com/Deeptiman/forgekey/go/src/mathutils"
	"github.com/stretchr/testify/assert"
	"math/big"
	"testing"
)

func TestFindPrimitiveRootsForKyber(t *testing.T) {
	KyberQ := uint64(3329)
	KyberOrder := uint64(256)
	qBig := new(big.Int).SetUint64(KyberOrder)
	factors := FactorByPollardRho(qBig)
	assert.Equal(t, uint64(17), FindPrimitiveRoots(KyberQ, KyberOrder, factors))
}

func TestFindPrimitiveRootsForDilithium(t *testing.T) {
	DilithiumQ := uint64(8380417)
	DilithiumOrder := uint64(512)
	qBig := new(big.Int).SetUint64(DilithiumOrder)
	factors := FactorByPollardRho(qBig)
	assert.Equal(t, uint64(1753), FindPrimitiveRoots(DilithiumQ, DilithiumOrder, factors))
}

func TestFindPrimitiveRootsForHomomorphic(t *testing.T) {
	testCases := []struct {
		modulus uint64
		factors []uint64
	}{
		{
			modulus: 36028796482093056,
			factors: []uint64{2, 3, 2731, 8191},
		},
		{
			modulus: 18014399046352896,
			factors: []uint64{2, 3, 11, 251, 4051},
		},
	}
	for _, testCase := range testCases {
		t.Run(fmt.Sprintf("Find primitive root = [%d] ", testCase.modulus), func(t *testing.T) {
			Q := mathutils.NewBigInt().SetUint64(testCase.modulus)
			factors := WithECM().GetFactor(Q)
			assert.Equal(t, testCase.factors, factors)
			assert.Equal(t, uint64(2), FindPrimitiveRoots(testCase.modulus, testCase.modulus, factors))
		})
	}
}
