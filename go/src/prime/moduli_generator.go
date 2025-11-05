package prime

import (
	"math"
)

// GenerateModuliChain
//
// LogN = Maximum degree of a polynomial
// LogQ = Ciphertext Modulus
// LogP = Auxiliary Modulus
// LogNthRoot = 2 * LogN
// NTT Friendly Prime: Qi, Pi ≡ 1 (mod 2N)
// Prime needs to be as closer to 2^{BitSize} + 1
//
// Run this code: https://go.dev/play/p/qPgw0zY1jbe
func GenerateModuliChain(logN int, logQ, logP []int) (Qi, Pi []uint64) {
	LogNthRoot := 2 * logN
	NthRoot := uint64(1 << LogNthRoot)

	bitSizes := make([]int, 0, len(logQ)+len(logP))
	bitSizes = append(logQ, logP...)

	Qi = make([]uint64, len(logQ))
	Pi = make([]uint64, len(logP))
	usedPrimes := make(map[uint64]bool)

	idxQ, idxP := 0, 0
	for _, bitSize := range bitSizes {
		if idxQ >= len(logQ) && idxP >= len(logP) {
			break
		}
		upperBit := uint64(1<<bitSize) + 1
		lowerBit := upperBit
		for isBitSizeOverflows(bitSize, upperBit, lowerBit, NthRoot) {
			if idxQ < len(logQ) && logQ[idxQ] == bitSize && !usedPrimes[upperBit] && isPrime(upperBit) {
				Qi[idxQ] = upperBit
				usedPrimes[upperBit] = true
				idxQ++
				break
			}

			if idxQ < len(logQ) && logQ[idxQ] == bitSize && !usedPrimes[lowerBit] && isPrime(lowerBit) {
				Qi[idxQ] = lowerBit
				usedPrimes[lowerBit] = true
				idxQ++
				break
			}

			if idxP < len(logP) && logP[idxP] == bitSize && !usedPrimes[upperBit] && isPrime(upperBit) {
				Pi[idxP] = upperBit
				usedPrimes[upperBit] = true
				idxP++
				break
			}

			if idxP < len(logP) && logP[idxP] == bitSize && !usedPrimes[lowerBit] && isPrime(lowerBit) {
				Pi[idxP] = lowerBit
				usedPrimes[lowerBit] = true
				idxP++
				break
			}
			upperBit += NthRoot
			lowerBit -= NthRoot
		}
	}
	return Qi, Pi
}

func isBitSizeOverflows(bitSize int, upperBit, lowerBit, NthRoot uint64) bool {
	return (math.Log2(float64(upperBit))-float64(bitSize) < 0.5 ||
		upperBit < 0xffffffffffffffff-NthRoot) ||
		(float64(bitSize)-math.Log2(float64(lowerBit)) < 0.5 || lowerBit > NthRoot)
}

func isPrime(x uint64) bool {
	return probablePrime(x, MAX_PRIMALITY_CHECK)
}
