package sampler

import (
	"fmt"
	"math/rand"
)

type SamplingMethod string

const (
	GAUSSIAN SamplingMethod = "Gaussian"
	ZIGGURAT SamplingMethod = "Ziggurat"
)

// Poly represents a polynomial in Ring-LWE with coefficients factored across multiple moduli.
type Poly struct {
	Coeffs [][]int64
}

// Sampler holds the precomputed moduli chain, entropy source and sampling methods to generate discrete Gaussian
// noise in Ring-LWE based crypto system.
type Sampler struct {
	// N is the polynomial degree (number of coefficients), must be power of 2.
	N int
	// moduliQ is the primary RNS moduli chain for NTT domain (Q ≡ 1 mod 2N).
	moduliQ []uint64
	// moduliP is the extended RNS moduli chain for CRT reconstruction to Ring R_QP.
	moduliP []uint64
	// seed is the 64-bit entropy seed extracted from `crypto/rand`.
	seed int64
	// entropy is the entropy source defining the CSPNG for both sampling method (Gaussian, Ziggurat).
	entropy *rand.Rand
	// method is the supported sampling algorithms: Gaussian Sampling (rejection), Ziggurat Sampling (table-based).
	method SamplingMethod
}

func NewSampler(logN int, moduliQ, moduliP []uint64) *Sampler {
	return &Sampler{
		N:       1 << logN,
		moduliQ: moduliQ,
		moduliP: moduliP,
	}
}

func (s *Sampler) GenerateCoefficients() Poly {
	if err := s.EntropySource(); err != nil {
		panic(fmt.Errorf("failed to generate entropy source=%v", err))
	}
	switch s.method {
	case GAUSSIAN:
		mean := 0.0
		sigma := 2.0
		minRange, maxRange := int64(-6), int64(6)
		return s.GenerateNoisyPolynomial(s.N, mean, sigma, minRange, maxRange)
	case ZIGGURAT:
		//TODO: Implement Ziggurat Sampler
	default:
		panic("choose sampling method between GAUSSIAN or ZIGGURAT")
	}
	return Poly{}
}
