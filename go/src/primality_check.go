package src

import (
	"crypto/rand"
	"math"
	"math/big"
)

const MAX_PRIMALITY_CHECK = 5

func probablePrime(n uint64, k int) bool {
	if n < 2 {
		// If n=2 then it's cannot be computed as modular reduction. There has to be a prime factor of 2^n to generate modular residues
		// of few sets that can be used for modular reduction against a large number.
		return false
	}

	// Try to check with a small range of prime number to if n is prime. This technique largely beneficial if the n is small prime number
	// and can generate a range of moduli to compute quick modular reduction.
	for _, p := range []uint64{2, 3, 5, 7, 11, 13, 17, 19, 23, 29} {
		if n%p == 0 {
			return n == p
		}
	}

	s, d := 0, n-1
	for d%2 == 0 {
		// Increment [s] to keep count how many times [n-1] divided with 2 and reduce [d].
		s = s + 1
		// Reduce [d] by dividing with 2 until [d] is odd.
		d = d / 2
	}

	// Try a small range of iteration (k) to repeatedly test if odd number [d] can be factor with modulus n using a random-number (a).
	for i := 0; i < k; i++ {
		maxNumber := big.NewInt(math.MaxUint32)
		bigNum, err := rand.Int(rand.Reader, maxNumber)
		if err != nil {
			panic(err)
		}
		a := bigNum.Uint64()
		// x = a^d mod n
		x := findModulus(a, d, n)
		if x == 1 || x == n-1 {
			continue
		}

		j := 0
		for ; j < s-1; j++ {
			x = findModulus(x, 2, n)
			// x cannot be a prime in any case otherwise the iteration of proving the [n] as composite number will break.
			if x == n-1 {
				break
			}
		}
		if j == s {
			return false
		}
	}
	return true
}

func findModulus(base, exponent, modulus uint64) uint64 {
	result := uint64(1)
	// This approach will be faster to compute modulus of base & exponent using modular exponentiation technique.
	//
	// If we compute (x = base ^ exponent mod modulus) then it would be computationally slower for larger number to do
	// a modular reduction.
	//
	// We can use a square & multiply algorithm to use the square of base and do modulus against (n) then keep repeating
	// until all the bits are processed. For even large modulus if we do this technique then base will be within the modulus and
	// will avoid overflow issue.
	base = base % modulus
	for exponent > 0 {
		if exponent%2 == 1 {
			result = (result * base) % modulus
		}
		exponent >>= 1
		base = (base * base) % modulus
	}
	return result
}

func generatePrime(bits, k int) uint64 {
	for {
		x, err := rand.Int(rand.Reader, big.NewInt(100))
		if err != nil {
			return uint64(1)
		}
		n := x.Uint64()

		// n |= (1 << (bits - 1)) | 1
		//
		// This bits masking ensure [n] remains to be an ODD number.
		//
		// 1. Left shift bits = 64, so (1 << (bits - 1)) will result 1 to the 64th bit position (most significant bit) and also into a 64-bit integer.
		// In binary = 1000000000000000000000000000000000000000000000000000000000000000
		// In hex = 0x8000000000000000
		//
		// 2. OR operation with 1 ( | 1), will result the least-significant bits to be always 1. And overall the number [n] will
		// be an ODD number.
		//
		// 3. OR operation with n |= , will set the most-significant bit to 1 which means for 64-bits length [n] has the highest bit number due to ((1 << (bits - 1))). Also the least-significant
		// bits remain as 1 due to (|1). So, n can be an odd number.
		n |= (1 << (bits - 1)) | 1

		// If bits is less than 64-bits then ODD number [n] needs to within the range to prevent overflows.
		if bits < 64 {
			// 1. For bits = 32, (1 << bits) will set the bits as 0 because the shifting covers the complete width of the bits-length and no other bits left to claims a position.
			// 2. Subtracting - 1, will results in 0, will set all bits to 1 in unsigned arithmetic and advantage is to cover the entire integer width. Also, to keep the all the least-significant bits to 1 and will be useful
			// for further bits-masking operation.
			// 3. And &= of p with each bit will ensure corresponding bit will be set to 1 only if both bits are 1.
			n &= (1 << bits) - 1
		}
		if probablePrime(n, k) {
			return n
		}
	}
}
