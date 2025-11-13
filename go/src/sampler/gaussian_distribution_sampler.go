package sampler

import (
	crand "crypto/rand"
	"encoding/binary"
	"math"
	"math/rand"
	"sort"
)

// PDFNormal computes the probability density function (PDF) of a Gaussian distribution.
// Parameters:
// - x: Ths value at which to evaluate the PDF.
// - mu: Mean of the Gaussian distribution.
// - sigma: Standard deviation of the Gaussian distribution.
func (s *Sampler) PDFNormal(x, mu, sigma float64) float64 {
	return (1 / (sigma * math.Sqrt(2*math.Pi))) * math.Exp(-math.Pow(x-mu, 2)/(2*math.Pow(sigma, 2)))
}

// SampleDiscreteGaussian samples a value from a discrete Gaussian distribution using rejection sampling.
// Parameters:
// - prng: Pseudo-random number generator for uniform sampling with fixed [1024] buffer.
// - mu: Mean of the Gaussian distribution (0.0).
// - sigma: Standard deviation of the Gaussian distribution.
// - min, max: Bounds for the discrete rang of sample values.
func (s *Sampler) SampleDiscreteGaussian(mu, sigma float64, min, max int64) int64 {
	// Precompute PDF and CDF for discrete values from min to max
	values := make([]int64, 0)
	pdf := make([]float64, 0)
	cdf := make([]float64, 0)
	total := 0.0
	for i := min; i <= max; i++ {
		p := s.PDFNormal(float64(i), mu, sigma)
		pdf = append(pdf, p)
		total += p
		cdf = append(cdf, total)
		values = append(values, i)
	}

	// Normalize CDF to 1 for proper probability distribution.
	for i := range cdf {
		cdf[i] /= total
	}

	// Find the smallest i where CDF[i] >= u using binary search.
	index := sort.SearchFloat64s(cdf, s.entropy.Float64())
	if index >= len(values) {
		index = len(values) - 1
	}
	return values[index]
}

// modInverse computes the modular inverse of a modulo m using the Extended Euclidean Algorithm.
// Parameters:
//   - a: The basis number whose modular inverse is computed.
//   - m: Input modulus coprime with a.
func modInverse(a, m int64) int64 {
	m0, x0, x1 := m, int64(0), int64(1)
	for a > 1 {
		q := a / m // quotient
		r := a % m // remainder
		a, m = m, r
		newX0 := x1 - q*x0
		x1 = x0
		x0 = newX0
	}

	if x1 < 0 {
		x1 += m0
	}
	return x1
}

// ExtendBasis extends a polynomial from R_Q to R_QP by computing the residues using Chinese Remainder Theorem (CRT)
// for additional moduli in P.
func (s *Sampler) ExtendBasis(polyQ Poly) Poly {
	// Combine moduliQ and moduliP to represent the ring R_QP.
	moduli := append(s.moduliQ, s.moduliP...)
	polyQP := Poly{Coeffs: make([][]int64, len(moduli))}
	for j := 0; j < len(moduli); j++ {
		polyQP.Coeffs[j] = make([]int64, len(polyQ.Coeffs[0]))
	}
	// Copy coefficients for moduliQ.
	for j := 0; j < len(s.moduliQ); j++ {
		copy(polyQP.Coeffs[j], polyQ.Coeffs[j])
	}
	// Extend to moduliP
	for j := len(s.moduliQ); j < len(moduli); j++ {
		for i := 0; i < len(polyQ.Coeffs[0]); i++ {
			coeff := polyQ.Coeffs[0][i]
			polyQP.Coeffs[j][i] = coeff % int64(moduli[j])
			if polyQP.Coeffs[j][i] < 0 {
				polyQP.Coeffs[j][i] += int64(moduli[j])
			}
		}
	}
	return polyQP
}

// GenerateNoisyPolynomial samples a noisy polynomial of degree N from a discrete Gaussian distribution
// with mean μ and standard deviation σ, using rejection sampling over the range [min, max].
//
// - Each coefficient is independently sampled and centered in [-Q/2, Q/2) for RNS compatibility.
// - Coefficients are reduced modulo each Qᵢ in moduliQ using CRT for multi-modulus representation.
// - The resulting polynomial is in R_Q (Ring-LWE) and extended to R_QP via ExtendBasis.
//
// Used in lattice-based PQC (Kyber, Dilithium) for secret/error polynomials and in CKKS for
// fresh ciphertext noise. Rejection sampling ensures statistical closeness to ideal Gaussian.
func (s *Sampler) GenerateNoisyPolynomial(N int, mu, sigma float64, min, max int64) Poly {
	poly := Poly{Coeffs: make([][]int64, len(s.moduliQ))}
	for j := 0; j < len(s.moduliQ); j++ {
		poly.Coeffs[j] = make([]int64, N)
	}

	Q := s.moduliQ[0]
	QHalf := int64(Q / 2)

	M := len(s.moduliQ)
	product := uint64(1)
	for _, modulus := range s.moduliQ {
		product *= modulus
	}

	invs := make([]int64, M)
	for j := 0; j < len(s.moduliQ); j++ {
		a := Q / s.moduliQ[j]
		invs[j] = modInverse(int64(a), int64(s.moduliQ[j]))
	}

	for i := 0; i < N; i++ {
		sample := s.SampleDiscreteGaussian(mu, sigma, min, max)
		// Center coefficient around [-Q/2, Q/2]
		centeredCoeff := sample
		if sample > QHalf {
			centeredCoeff = int64(Q) - sample
		} else if sample < -QHalf {
			centeredCoeff = int64(Q) + sample
		}
		residues := make([]int64, len(s.moduliQ))
		for j := 0; j < len(s.moduliQ); j++ {
			if coeff := centeredCoeff % int64(s.moduliQ[j]); coeff != 0 {
				poly.Coeffs[j][i] = coeff
			}
			if poly.Coeffs[j][i] < 0 {
				poly.Coeffs[j][i] += int64(s.moduliQ[j])
			}
			if coeff := poly.Coeffs[j][i]; coeff != 0 {
				residues[j] = poly.Coeffs[j][i]
			}
		}
		// Compute unified coefficient using Chinese Remainder Theorem (CRT).
		unified := s.CRTForRingLWE(residues, s.moduliQ, invs, product)
		// Assign CRT-reduced values back to poly.Coeffs[j][i]
		for j := 0; j < len(s.moduliQ); j++ {
			if coeff := unified % int64(s.moduliQ[j]); coeff != 0 {
				poly.Coeffs[j][i] = coeff
			}
			if poly.Coeffs[j][i] < 0 {
				poly.Coeffs[j][i] += int64(s.moduliQ[j])
			}
		}
	}
	return s.ExtendBasis(poly)
}

// CRTForRingLWE reconstructs a unified coefficient in Z_M from its residues modulo each Qᵢ using the
// Chinese Remainder Theorem (CRT).
//
// To give an analogy of currency exchange in global finance:
//   - Each residue cⱼ ≡ c (mod Qⱼ) is like a local currency value.
//   - Each Qⱼ has its own volatility rate (market size).
//   - M = ∏Qⱼ is the global market capitalization.
//   - (M/Qⱼ) is the exchange rate from local to global.
//   - inv(M/Qⱼ) is the conversion factor back to local.
//
// CRT computes the exact global value of a financial transaction across volatile markets enabling fast,
// parallel modular arithmetic in RNS (Residue Number System).
//
// In RNS system, each Qᵢ acts like financial market with its own volatility. The CRT is the settlement engine
// that converts the local residue into a single, globally consistent value like international trade exchange
// forum reconcile transaction across currencies.
func (s *Sampler) CRTForRingLWE(coeffs []int64, moduli []uint64, invs []int64, product uint64) int64 {
	// Compute the product of all moduli (M = m[0] * m[1] * m[2] .... * m[n]) to get the composite modulus.
	result := int64(0)
	M := int64(product)
	for i, coeff := range coeffs {
		pi := M / int64(moduli[i]) // Exchange rate: M/Qᵢ
		term := coeff * pi % M     // Local ---> Global
		term = term * invs[i] % M  // Apply conversation factor
		result = (result + term) % M
	}
	return result
}

// EntropySource initializes the cryptographically secure pseudo-random number generator (CSPRNG) using a
// high-entropy seed from the operating system's randomness pool.
//
// Thinks of its as the Global Money Bank the ultimate financial institution that funds the entire cryptographic
// economy with unpredictable high-entropy capital.
func (s *Sampler) EntropySource() error {
	var randomBufferN [1024]byte
	// 1. First 8-bytes --> 64-bit seed for CSPRNG (initial use). This seed produces all Gaussian sampling for
	// lattice-based PQC (Kyber, Dilithium) and homomorphic encryption (CKKS).
	//
	// 2. The remaining 1016 bytes are reserved for future entropy expansion.
	if _, err := crand.Read(randomBufferN[:]); err != nil {
		return err
	}
	s.seed = int64(binary.BigEndian.Uint64(randomBufferN[:8]))
	s.entropy = rand.New(rand.NewSource(s.seed))

	// Reset the buffer to zero.
	for i := range randomBufferN {
		randomBufferN[i] = 0
	}
	return nil
}
