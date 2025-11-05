package prime

import (
	"fmt"
	"github.com/Deeptiman/ntt-hardware-accelerator/go/src"
	"github.com/stretchr/testify/assert"
	"math/big"
	"testing"
)

func TestGenerateModuliChain(t *testing.T) {
	N := 16
	logQ := []int{56, 55, 55, 54, 54, 54}
	logP := []int{55, 55}

	expectedQi := []uint64{72057594037927937, 36028805608898561, 36028788429029377, 18014394214514689, 18014407099416577, 18014372739678209}
	expectedPi := []uint64{36028814198833153, 36028818493800449}
	Qi, Pi := GenerateModuliChain(N, logQ, logP)
	fmt.Println("Qi = ", Qi)
	fmt.Println("Pi = ", Pi)
	assert.Equal(t, Qi, expectedQi)
	assert.Equal(t, Pi, expectedPi)
}

func TestGeneratePrime(t *testing.T) {
	primeNumber := src.generatePrime(64, 5)
	bigNum := new(big.Int)
	assert.True(t, bigNum.SetUint64(primeNumber).ProbablyPrime(5))
}
