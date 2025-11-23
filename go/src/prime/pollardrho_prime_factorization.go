package prime

import (
	"crypto/rand"
	"github.com/Deeptiman/forgekey/go/src/utils"
	"math/big"
)

func pollardRho(n *big.Int) *big.Int {
	one := big.NewInt(1)
	if n.Cmp(one) == 0 {
		return n
	}

	// if n is even then return
	if new(big.Int).Mod(n, big.NewInt(2)).Cmp(big.NewInt(0)) == 0 {
		return big.NewInt(2)
	}

	// if n is prime then return
	if isPrime(n.Uint64()) {
		return new(big.Int).Set(n)
	}

	MAX_ATTEMPTS := 6
	for attempts := 0; attempts < MAX_ATTEMPTS; attempts++ {
		// first: random within [1, n-1]
		c, err := rand.Int(rand.Reader, new(big.Int).Sub(n, one))
		if err != nil {
			c = big.NewInt(int64(attempts + 1)) // set any deterministic number.
		}
		c.Add(c, one)

		// second: random within [2, n-2]
		x, err := rand.Int(rand.Reader, new(big.Int).Sub(n, one))
		if err != nil {
			x = big.NewInt(2) // pick one for starting point.
		}
		x.Add(x, one)

		y := new(big.Int).Set(x)
		d := big.NewInt(1)
		maxIter := 200000
		for i := 0; i < maxIter; i++ {
			// x = (x * x + c) % n
			x.Mul(x, x).Add(x, c).Mod(x, n)

			// y = g(g(y)) (mod n)
			//
			// where g(x) = (x * x + c) (mod n)
			//
			// It's a two-time dial used from Floyd's cycle-finding algorithm
			y.Mul(y, y).Add(y, c).Mod(y, n)
			y.Mul(y, y).Add(y, c).Mod(y, n)

			diff := utils.Abs(new(big.Int).Sub(x, y))
			d.GCD(nil, nil, diff, n) // gcd(|x-y|, n)
		}

		if d.Cmp(one) != 0 && d.Cmp(n) != 0 {
			return d // found the non-trivial factor
		}
	}
	return new(big.Int).Set(n) // no factor found
}

// FactorByPollardRho finds the prime factors by applying PollardRho technique.
func FactorByPollardRho(n *big.Int) []uint64 {
	n = new(big.Int).Set(n)
	zero := big.NewInt(0)
	one := big.NewInt(1)
	two := big.NewInt(2)

	var factors []uint64

	// test: trial divide by 2
	for new(big.Int).Mod(n, two).Cmp(zero) == 0 {
		factors = append(factors, 2)
		n.Div(n, two)
	}

	// small primes trial division up to a modest bound (removes small primes fast)
	for p := int64(3); p <= 1000 && n.Cmp(one) > 0; p += 2 {
		pCpy := big.NewInt(p)
		for new(big.Int).Mod(n, pCpy).Cmp(zero) == 0 {
			factors = append(factors, uint64(p))
			n.Div(n, pCpy)
		}
	}

	// if n is 1, then found the non-trivial factors within small primes range
	if n.Cmp(one) == 0 {
		return factors
	}

	// stack for recursive attempts over each composite number PollardRho can produce over
	// the n
	stack := []*big.Int{n}
	for len(stack) > 0 {
		m := stack[len(stack)-1]
		stack = stack[:len(stack)-1]

		// if m is prime then add to factor and continue
		if isPrime(m.Uint64()) {
			factors = append(factors, m.Uint64())
			continue
		}

		d := pollardRho(m)
		if d.Cmp(m) == 0 {
			factors = append(factors, m.Uint64())
			continue
		}
		// attempts with more possible factoring
		f := new(big.Int).Div(m, d)
		stack = append(stack, d)
		stack = append(stack, f)
	}
	return factors
}
