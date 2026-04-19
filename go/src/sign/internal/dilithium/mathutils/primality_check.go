package mathutils

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
