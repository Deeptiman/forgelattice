package src

import (
	"fmt"
	"math"
	"math/big"
	"math/rand"
	"time"
)

type Algorithm string

const (
	PollardRho Algorithm = "PollardRho"
	ECM        Algorithm = "Elliptic_Curve_Method"

	maxTorsion = 12
	Log        = "PRIME_FACTOR"
)

// Point represents a point (x, y) on the curve.
type Point struct {
	X, Y *big.Int
}

type Curve struct {
	A *big.Int
	B *big.Int
	M *big.Int
	J *big.Int
}

type ECMConfig struct {
	// Smooth B for computing factors within bound.
	B             int64
	Seed          int64
	MaxCurves     int
	MaxSmallPrime int64
	MaxTorsion    int
	MaxPointTries int
}

// GetPrimeFactor returns the prime factorization of given modulus by applying PollardRho and ECM factorization
// technique.
func GetPrimeFactor(q *big.Int, algo Algorithm) []uint64 {
	switch algo {
	case PollardRho:
		return FactorByPollardRho(q)
	case ECM:
		return WithECM().GetFactor(q)
	default:
		factors := FactorByPollardRho(q)
		if len(factors) == 0 {
			return WithECM().GetFactor(q)
		}
		return factors
	}
}

func pollardRho(x, c, q *big.Int) (y *big.Int) {
	y = new(big.Int).Exp(x, new(big.Int).SetUint64(2), q)
	y.Add(y, c)
	y.Mod(y, q)
	return y
}

// FactorByPollardRho finds the prime factorization using PollardRho algorithm.
func FactorByPollardRho(q *big.Int) []uint64 {
	zero := new(big.Int).SetUint64(0)
	one := new(big.Int).SetUint64(1)
	diff := new(big.Int)
	factors := make([]uint64, 0)

	for q.Cmp(one) != 0 {
		if isPrime(q.Uint64()) {
			return append(factors, q.Uint64())
		}

		x := new(big.Int).SetUint64(2)
		y := new(big.Int).SetUint64(2)
		for i := 2; i < 10; i++ {
			c := new(big.Int).SetUint64(uint64(i))
			e := new(big.Int)
			factor := new(big.Int).SetUint64(1)

			for factor.Cmp(zero) != 0 && factor.Cmp(q) != 0 {
				x = pollardRho(x, c, q)
				y = pollardRho(pollardRho(y, c, q), c, q)
				if factor.GCD(nil, nil, diff.Sub(x, y), q); factor.Cmp(one) != 0 {
					factors = append(factors, factor.Uint64())
					for e.Mod(q, factor).Cmp(zero) == 0 {
						q.Quo(q, factor)
					}
					if q.Cmp(one) == 0 {
						return factors
					}
				}
			}
		}
	}
	return factors
}

// WithECM returns a default configuration for running the Elliptic Curve Method (ECM) for integer factorization.
func WithECM() *ECMConfig {
	return &ECMConfig{
		B:             10000,
		Seed:          time.Now().UnixNano(),
		MaxCurves:     100,
		MaxSmallPrime: 10000,
		MaxPointTries: 100,
	}
}

// GetFactorByECM attempts to find a non-trivial factor of the curve's modulus by performing point addition and doubling
// on a single elliptic curve. This is a simplified but accurate Phase 1 implementation of ECM (no Phase 2 for brevity).
//
// First: Torsion check for small multiples (up to 12P).
// Then: Phase 1 - Compute Q = kP where k = lcm(1..B) using efficient scalar multiplication.
// Checks for factors via GCD during operations.
func (e *ECMConfig) GetFactorByECM(c Curve, P Point) (*big.Int, error) {
	one := big.NewInt(1)

	// Step 1: Torsion Check (small nP)
	factor := c.WithTorsionPoints(P)
	if factor.Cmp(one) != 0 {
		return factor, nil
	}

	// Step 2: Compute lcm(1..B) - product of highest prime powers <= B
	k := computeLCMUpTo(e.B)

	// Step 3: Efficient scalar multiplication Q = k * P
	// Use binary exponentiation with doubling and additions, checking factors
	factor, err := scalarMultiply(c, P, k)
	if err != nil {
		if factor.Cmp(one) > 0 {
			return factor, nil
		}
	}
	if factor.Cmp(one) != 0 {
		return factor, nil
	}

	return one, fmt.Errorf("no factor found for curve with j=%v", c.J)
}

// computeLCMUpTo computes lcm up to n efficiently.
func computeLCMUpTo(n int64) *big.Int {
	lcm := big.NewInt(1)
	for p := int64(2); p <= n; p++ {
		if isPrime(big.NewInt(p).Uint64()) {
			maxPow := int64(1)
			for pow := p; pow <= n; pow *= p {
				maxPow = pow
			}
			lcm.Mul(lcm, big.NewInt(maxPow))
		}
	}
	return lcm
}

// scalarMultiply Scalar multiplication R = k * P with factor checks
func scalarMultiply(c Curve, P Point, k *big.Int) (*big.Int, error) {
	one := big.NewInt(1)
	R := Point{nil, nil} // Point at Infinity
	for k.BitLen() > 0 { // iterate each bit up to the given bit len.
		if k.Bit(0) == 1 {
			// If the least significant bit (LSB) of k is 1 then k is odd, add the current P to the accumulator R.
			var factor *big.Int
			var err error
			R, factor, err = c.PointAdd(R, P)
			if err != nil && factor.Cmp(one) > 0 {
				return factor, err
			}
		}
		var factor *big.Int
		var err error
		P, factor, err = c.PointAdd(P, P) // Double P, 2P, 3P, 4P ... nP
		if err != nil && factor.Cmp(one) > 0 {
			return factor, err
		}
		k.Rsh(k, 1)
	}
	return one, nil
}

// GetFactor finds the prime factorizations of given modulus M.
func (e *ECMConfig) GetFactor(q *big.Int) []uint64 {
	factors, m, err := SmallFactors(q, e.MaxSmallPrime)
	if err != nil {
		fmt.Println(Log, "No Factor found within [2-", e.MaxSmallPrime, "] range", "Error", err.Error())
	}

	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	for m.Cmp(big.NewInt(1)) != 0 && m.ProbablyPrime(60) {
		fmt.Println("Traverse Curve == ", m)
		for i := 0; i < e.MaxCurves; i++ {
			curve, point, curveErr := e.InitializeWeierstrassCurve(m, r)
			if curveErr != nil {
				fmt.Println("CurveErr = ", curveErr)
				continue
			}

			factor, curveErr := e.GetFactorByECM(curve, point)
			if curveErr == nil && factor.Cmp(big.NewInt(1)) != 0 && factor.Cmp(curve.M) != 0 {
				factors = append(factors, factor.Uint64())
				for c := new(big.Int); c.Mod(m, factor).Cmp(big.NewInt(0)) == 0; {
					m.Quo(m, factor)
				}
				if m.Cmp(big.NewInt(1)) == 0 {
					return factors
				}
			}
		}
	}
	return factors
}

// PreComputePrimes returns a set of prime numbers computed using Sieve of Eratosthenes algorithm.
func PreComputePrimes(maxPrime int64) []uint64 {
	n := int(maxPrime)
	sieve := make([]bool, n+1)
	for i := 0; i <= n; i++ {
		sieve[i] = true
	}

	sieve[0], sieve[1] = false, false
	for i := 2; i <= int(math.Sqrt(float64(n))); i++ {
		if sieve[i] {
			for j := i * i; j <= n; j += i {
				sieve[j] = false
			}
		}
	}

	primes := make([]uint64, 0)
	for i := 2; i <= n; i++ {
		if sieve[i] {
			primes = append(primes, uint64(i))
		}
	}
	return primes
}

// SmallFactors runs a small range of primality check and attempts to find factor of given modulus.
func SmallFactors(q *big.Int, maxPrime int64) ([]uint64, *big.Int, error) {
	zero := new(big.Int).SetUint64(0)
	one := new(big.Int).SetUint64(1)
	m := new(big.Int).Set(q)
	c := new(big.Int)

	factors := make([]uint64, 0)
	primes := PreComputePrimes(maxPrime)
	for i := 0; i < len(primes); i++ {
		prime := new(big.Int).SetUint64(primes[i])
		multiplicity := 0
		for c.Mod(m, prime).Cmp(zero) == 0 {
			m.Quo(m, prime)
			multiplicity++
		}
		if multiplicity > 0 {
			factors = append(factors, primes[i])
			if m.Cmp(one) == 0 {
				return factors, m, nil
			}
		}
	}

	return factors, m, nil
}

// GCD finds the common divisor between two integers.
func GCD(a, b *big.Int) *big.Int {
	zero := big.NewInt(0)
	g := new(big.Int).Abs(a)
	bAbs := new(big.Int).Abs(b)
	for bAbs.Cmp(zero) != 0 {
		g, bAbs = bAbs, new(big.Int).Mod(g, bAbs)
	}
	return g
}

// computeJInvariant
//
//	              4a³
//	j = 1728 * -----------  (mod M)
//	            4a³ + 27b²
func computeJInvariant(a, b, M *big.Int) (*big.Int, error) {
	fourA3 := new(big.Int).Mul(big.NewInt(4), new(big.Int).Mul(a, new(big.Int).Mul(a, a)))
	twentySevenBSquare := new(big.Int).Mul(big.NewInt(27), new(big.Int).Mul(b, b))
	denominator := new(big.Int).Add(fourA3, twentySevenBSquare)
	denominator.Mod(denominator, M)

	inv, _, err := ModInverse(denominator, M)
	if err != nil {
		return nil, err
	}

	j := new(big.Int).Mul(big.NewInt(1728), fourA3)
	j.Mul(j, inv)
	j.Mod(j, M)
	return j, nil
}

// InitializeWeierstrassCurve generates random curve y² = x³ + Ax + B (mod M) with j-invariant group
// order.
func (e *ECMConfig) InitializeWeierstrassCurve(modulus *big.Int, r *rand.Rand) (Curve, Point, error) {
	zero := big.NewInt(0)
	one := big.NewInt(1)
	for i := 0; i < e.MaxPointTries; i++ {
		A := new(big.Int).Rand(r, modulus)
		x := new(big.Int).Rand(r, modulus)
		y := new(big.Int).Rand(r, modulus)

		// Compute B = y² - x * (x² - A)
		x2 := new(big.Int).Mul(x, x)
		x2MinusA := new(big.Int).Sub(x2, A)
		xTimesMinusA := new(big.Int).Mul(x, x2MinusA)
		y2 := new(big.Int).Mul(y, y)
		B := new(big.Int).Sub(y2, xTimesMinusA)
		B.Mod(B, modulus)

		// Compute discriminant: Δ = -16(4A³ + 27B²)
		minusA := new(big.Int).Neg(A)
		fourMinusA3 := new(big.Int).Mul(big.NewInt(4), new(big.Int).Mul(minusA, new(big.Int).Mul(minusA, minusA)))
		twentySevenB2 := new(big.Int).Mul(big.NewInt(27), new(big.Int).Mul(B, B))
		delta := new(big.Int).Sub(zero, new(big.Int).Mul(big.NewInt(16), new(big.Int).Add(fourMinusA3, twentySevenB2)))
		delta.Mod(delta, modulus)

		gcdDelta := GCD(delta, modulus)
		if gcdDelta.Cmp(one) != 0 {
			continue
		}

		j, err := computeJInvariant(minusA, B, modulus)
		if err != nil {
			continue
		}

		if j.Cmp(zero) == 0 || j.Cmp(big.NewInt(1728)) == 0 {
			continue
		}
		return Curve{minusA, B, modulus, j}, Point{x, y}, nil
	}
	return Curve{}, Point{}, fmt.Errorf("no valid curve and point after max %d attempts", e.MaxCurves)
}

// WithTorsionPoints attempts to run point addition and doubling between a fixed range points to find the
// non-trivial factor.
func (c *Curve) WithTorsionPoints(P Point) *big.Int {
	one := big.NewInt(1)
	var factor *big.Int
	var err error
	R := P
	for n := 1; n <= maxTorsion; n++ {
		R, factor, err = c.PointAdd(R, P)
		if err != nil {
			if factor.Cmp(one) > 0 && factor.Cmp(c.M) < 0 { // Non-trivial only
				return factor
			}
			return one // Trivial failure (e.g., gcd=M), no factor
		}
		if factor.Cmp(one) != 0 {
			if factor.Cmp(c.M) == 0 {
				return one
			}
			return factor
		}
		if R.X == nil && R.Y == nil {
			return one
		}
	}
	return one
}

// PointAdd performs point addition and doubling on the elliptic curve y² = x³ + ax + b (mod M),
// computing the sum of points P and Q.
//
// Scenarios:
//
// - If P or Q is infinity (X==nil && Y==nil), return the other.
//
// - If P.X == Q.X but Q.Y == -P.Y mod M (negation), return infinity.
//
//		3x² + a
//
//	  - If P == Q, if doubles P using the slope λ = ----------
//	    2y
//
//	    y₂ - y₁
//
// Else case, adds P and Q using λ = ---------
//
//	x₂ - x₁
//
// In operations, if denominator not invertible, compute GCD(denom, M) as potential factor.
func (c *Curve) PointAdd(P, Q Point) (Point, *big.Int, error) {
	one := big.NewInt(1)
	inf := Point{nil, nil}
	if P.X == nil && P.Y == nil {
		return Q, one, nil
	}
	if Q.X == nil && Q.Y == nil {
		return P, one, nil
	}

	// Normalize coordinates mod M
	pX := new(big.Int).Mod(P.X, c.M)
	pY := new(big.Int).Mod(P.Y, c.M)
	qX := new(big.Int).Mod(Q.X, c.M)
	qY := new(big.Int).Mod(Q.Y, c.M)

	result := Point{new(big.Int), new(big.Int)}
	var lambda, numerator, denominator *big.Int

	xDiff := new(big.Int).Sub(qX, pX)
	xDiff.Mod(xDiff, c.M)
	if xDiff.Cmp(big.NewInt(0)) == 0 {
		ySum := new(big.Int).Add(pY, qY)
		ySum.Mod(ySum, c.M)
		if ySum.Cmp(big.NewInt(0)) == 0 {
			return inf, one, nil // P + (-P) = infinity, no error/factor
		}
	}

	// Point doubling
	if pX.Cmp(qX) == 0 && pY.Cmp(qY) == 0 {
		numerator = new(big.Int).Mul(big.NewInt(3), new(big.Int).Mul(pX, pX))
		numerator.Add(numerator, c.A)
		numerator.Mod(numerator, c.M)
		denominator = new(big.Int).Mul(big.NewInt(2), pY)
		denominator.Mod(denominator, c.M)
	} else {
		numerator = new(big.Int).Sub(qY, pY)
		numerator.Mod(numerator, c.M)
		denominator = xDiff
	}

	inv, factor, err := ModInverse(denominator, c.M)
	if err != nil {
		if factor.Cmp(one) > 0 && factor.Cmp(c.M) < 0 {
			return inf, factor, err // Non-trivial factor found
		}
		return inf, factor, err
	}
	lambda = new(big.Int).Mul(numerator, inv)
	lambda.Mod(lambda, c.M)

	result.X.Mul(lambda, lambda)
	result.X.Sub(result.X, pX)
	result.X.Sub(result.X, qX)
	result.X.Mod(result.X, c.M)

	result.Y.Sub(pX, result.X)
	result.Y.Mul(lambda, result.Y)
	result.Y.Sub(result.Y, pY)
	result.Y.Mod(result.Y, c.M)

	return result, one, nil
}

// ModInverse computes the modular inverse of a mod n, returning inverse and GCD.
func ModInverse(a, b *big.Int) (*big.Int, *big.Int, error) {
	zero := big.NewInt(0)
	one := big.NewInt(1)
	g := new(big.Int).Set(a)
	n0 := new(big.Int).Set(b)
	x, y := big.NewInt(0), big.NewInt(1)
	lastX, lastY := big.NewInt(1), big.NewInt(0)
	for g.Cmp(zero) != 0 {
		quotient := new(big.Int).Div(n0, g)
		n0, g = g, new(big.Int).Mod(n0, g)
		lastX, x = x, new(big.Int).Sub(lastX, new(big.Int).Mul(quotient, x))
		lastY, y = y, new(big.Int).Sub(lastY, new(big.Int).Mul(quotient, y))
	}

	if n0.Cmp(one) != 0 {
		return nil, n0, fmt.Errorf("non-trivial GCD found: %v", n0)
	}
	if lastY.Sign() < 0 {
		lastY.Add(lastY, b)
	}
	return lastY, one, nil
}
