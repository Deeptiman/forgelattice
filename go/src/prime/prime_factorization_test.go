package prime

import (
	"fmt"
	"github.com/Deeptiman/forgekey/go/src/utils"
	"github.com/stretchr/testify/assert"
	"math/big"
	"math/rand"
	"testing"
	"time"
)

func TestGetPrimeFactor(t *testing.T) {
	testCases := []struct {
		modulus uint64
		factors []uint64
	}{
		{
			modulus: 72057594037927937,
			factors: []uint64{257, 5153},
		},
		{
			modulus: 131071000000131071,
			factors: []uint64{73, 137, 131071},
		},
		{
			modulus: 36028796750528513,
			factors: []uint64{41, 2113},
		},
		{
			modulus: 36028796482093056,
			factors: []uint64{2, 3, 2731, 8191},
		},
		{
			modulus: 18014399046352896,
			factors: []uint64{2, 3, 11, 251, 4051},
		},
		{
			modulus: 18014399314788352,
			factors: []uint64{2, 7},
		},
		{
			modulus: 18014397435740160,
			factors: []uint64{2, 3, 5, 7, 13, 17, 241},
		},
		{
			modulus: 2305843009211596800,
			factors: []uint64{2, 3, 5, 11, 17, 31, 41},
		},
		{
			modulus: 36028796482093057,
			factors: []uint64{},
		},
		{
			modulus: 18014399314788353,
			factors: []uint64{},
		},
		{
			modulus: 18014397435740161,
			factors: []uint64{},
		},
	}

	for _, testCase := range testCases {
		t.Run(fmt.Sprintf("Find factors for [%d] ", testCase.modulus), func(t *testing.T) {
			m := utils.NewBigInt().SetUint64(testCase.modulus)
			algorithms := []Algorithm{ECM}
			for _, algo := range algorithms {
				factors := GetPrimeFactor(m, algo)
				fmt.Println("Factors : ", algo, testCase.modulus, " -- ", factors, " == ", testCase.factors)
				assert.Equal(t, factors, testCase.factors)
			}
		})
	}
}

func TestInitializeWeierstrassCurve(t *testing.T) {
	var x uint64 = 72057594037927937
	m := new(big.Int).SetUint64(x)
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	_, _, e := WithECM().InitializeWeierstrassCurve(m, r)
	assert.Nil(t, e)
}

func TestFactorByPollardRho(t *testing.T) {
	n := big.NewInt(8380416) // q=8380417, Dilithium: q - 1
	assert.Equal(t, GetPrimeFactor(n, PollardRho), []uint64{2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 3, 11, 31})

	n = big.NewInt(3328) // q=3329, Kyber: q - 1
	assert.Equal(t, GetPrimeFactor(n, PollardRho), []uint64{2, 2, 2, 2, 2, 2, 2, 2, 13})
}
