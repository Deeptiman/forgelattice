package cpapke

import (
	"github.com/Deeptiman/forgelattice/go/src/kem/kyber/internal/common"
	"github.com/Deeptiman/forgelattice/go/src/kem/kyber/internal/poly"
)

const (
	N        = common.N
	Q        = common.Q
	PolySize = common.PolySize
	SeedSize = common.SeedSize
)

// Kyber implements the Kyber CPA-secure public-key encryption scheme.
//
// This struct maintains both public and private state required for encryption and decryption. It is
// NOT safe for direct use outside of a CCA-secure construction such as ML-KEM.
type Kyber struct {
	Params
	pk *PublicKey
	sk *PrivateKey
}

// GenerateKeyPair deterministically generates a Kyber CPA-PKE keypair from the provided seed.
//
// The seed is expanded into:
//
//   - rho: seed for public matrix A
//
//   - sigma: seed for sampling secret and error polynomials
//
//     This function performs:
//
//   - Generation of public matrix A using rejection sampling.
//
//   - Sampling of secret vector s.
//
//   - Sampling of error vector e.
//
//   - Computation of t = A*s + e
//
// SECURITY NOTE:
//
//	This key generation is used for IND-CPA security only. Domain separation and CCA-security are
//
// enforced at higher layer (ML-KEM).
func (p *Kyber) GenerateKeyPair(seed []byte) *Kyber {
	seedA, sigma := common.ExpandSeed(seed[:])

	// 1. Copy seed[:32] to rho.
	copy(p.pk.rho[:], seedA[:SeedSize])

	// 2. Generate public matrix (A) using rejection sampling.
	p.generatePublicMatrixA(&p.pk.rho, false)

	// 3. Sample secret vectors (s) using CBD as input seed sigma and nonce (i).
	for i := 0; i < p.K; i++ {
		p.sk.s[i].SampleNoise(sigma[:], uint8(i), p.Eta1)
	}

	for i := 0; i < p.K; i++ {
		p.sk.s[i].NTT()
	}

	for i := 0; i < p.K; i++ {
		p.sk.s[i].Reduce()
	}

	eh := make(poly.Vec, p.K)
	// 4. Sample error vector (e) using CBD as input seed sigma and nonce (K+i).
	for i := 0; i < p.K; i++ {
		eh[i].SampleNoise(sigma[:], uint8(p.K)+uint8(i), p.Eta1)
	}

	for i := 0; i < p.K; i++ {
		eh[i].NTT()
	}

	// 5. Compute t = A * s + e
	p.pk.t = make(poly.Vec, p.K)
	for i := 0; i < p.K; i++ {
		var t poly.Poly
		publicMatrix := p.pk.a[i]
		secretVector := p.sk.s
		for j := 0; j < p.K; j++ {
			t.PointWiseMul(&publicMatrix[j], &secretVector[j])
		}
		p.pk.t[i].Add(t)
		p.pk.t[i].ToMont() // Do montgomery reduction to every computed (t' = A * s).
	}

	// 5.1 Add the error vector (e) to (t)
	for i := 0; i < p.K; i++ {
		p.pk.t[i].Add(eh[i])
	}

	for i := 0; i < p.K; i++ {
		p.pk.t[i].Reduce() // Do final reduction to the computed (t).
	}

	p.Transpose()
	return &Kyber{p.Params, p.pk, p.sk}
}

func (p *Kyber) GetPublicKey() *PublicKey {
	return p.pk
}

func (p *Kyber) GetPrivateKey() *PrivateKey {
	return p.sk
}

// generatePublicMatrixA deterministically generates the public matrix A using rejection sampling from SHAKE128.
//
// Each matrix element is uniformly sampled modulo q.
//
// The transpose flag controls whether A or A^T is generated, which is required for encryption vs. key generation paths.
func (p *Kyber) generatePublicMatrixA(rho *[SeedSize]byte, transpose bool) {
	// 1. Gather 32-bytes random numbers (rho).
	// 2. Shake it with 128-bit for each row & column and rho bytes.
	// 3. Apply rejection sampler for each iteration to collect 12-bits of buffer.
	// 4. Add it to the polynomial coefficients.
	// 5. Complete the loop to generate KxK matrix uniform within [0 ... Q)
	for x := 0; x < p.K; x++ {
		for y := 0; y < p.K; y++ {
			if transpose {
				p.pk.a[x][y].RejectionSampling(rho, byte(x), byte(y))
			} else {
				p.pk.a[x][y].RejectionSampling(rho, byte(y), byte(x))
			}
		}
	}
}

// Encrypt performs Kyber CPA-PKE encryption.
//
// SECURITY NOTE:
//
//	This function is NOT CCA-secure. It MUST only be used inside a Fujisaki-Okamoto transform.
func (p *Kyber) Encrypt(ct, pt, seed []byte) {
	rh := make(poly.Vec, p.K)
	e1 := make(poly.Vec, p.K)
	var e2 poly.Poly

	// 1. Sample noise polynomials (r, e1, e2)
	for i := 0; i < p.K; i++ {
		rh[i].SampleNoise(seed, uint8(i), p.Eta1)
	}

	for i := 0; i < p.K; i++ {
		rh[i].NTT()
	}

	for i := 0; i < p.K; i++ {
		rh[i].Reduce()
	}

	for i := 0; i < p.K; i++ {
		e1[i].SampleNoise(seed, uint8(p.K)+uint8(i), p.Eta2)
	}
	e2.SampleNoise(seed, uint8(2*p.K), p.Eta2)

	// 2. Compute u = A^T * r + e1
	u := make(poly.Vec, p.K)
	for i := 0; i < p.K; i++ {
		var tmp poly.Poly
		for j := 0; j < p.K; j++ {
			tmp.PointWiseMul(&p.pk.a[i][j], &rh[j])
		}
		u[i].Add(tmp)
	}

	for i := 0; i < p.K; i++ {
		u[i].Reduce()
	}

	for i := 0; i < p.K; i++ {
		u[i].InvNTT()
	}

	for i := 0; i < p.K; i++ {
		u[i].Add(e1[i])
	}

	// 3. Compute v = t * r + e2 + m
	var v, m, tmp poly.Poly
	for i := 0; i < p.K; i++ {
		tmp.PointWiseMul(&p.pk.t[i], &rh[i])
	}
	v.Add(tmp)
	v.Reduce()
	v.InvNTT()

	m.DecompressMessage(pt)
	v.Add(m)
	v.Add(e2)

	for i := 0; i < p.K; i++ {
		u[i].Reduce()
	}
	v.Reduce()

	// 4. Compress (u, v) into ciphertext
	size := poly.CompressedPolySize(p.Du)
	for i := 0; i < p.K; i++ {
		u[i].Compress(p.Du, ct[size*i:])
	}
	v.Compress(p.Dv, ct[p.K*size:])
}

// Decrypt performs Kyber CPA-PKE decryption.
//
// It recovers the message polynomial by computing:
//
//	m = v - s^T * u
//
// SECURITY NOTE:
//
//	Decryption does NOT perform ciphertext validation. Any integrity or validity checks MUST be
//	enforced by the caller (ML-KEM).
func (p *Kyber) Decrypt(pt []byte, ct []byte) {
	var u poly.Vec
	var v, m poly.Poly

	size := poly.CompressedPolySize(p.Du)
	u = make(poly.Vec, p.K)
	for i := 0; i < p.K; i++ {
		u[i].Decompress(p.Du, ct[size*i:])
	}
	v.Decompress(p.Dv, ct[p.K*size:])

	for i := 0; i < p.K; i++ {
		u[i].NTT()
	}

	var tmp poly.Poly
	for i := 0; i < p.K; i++ {
		tmp.PointWiseMul(&p.sk.s[i], &u[i])
	}
	m.Add(tmp)
	m.Reduce()
	m.InvNTT()
	m.Sub(v)
	m.Reduce()
	m.CompressMessage(pt)
}

// Transpose transposes the public matrix A in-place.
//
// This is required because Kyber encryption uses A^T while key generation uses A.
func (p *Kyber) Transpose() {
	for i := 0; i < p.K-1; i++ {
		for j := i + 1; j < p.K; j++ {
			t := p.pk.a[i][j]
			p.pk.a[i][j] = p.pk.a[j][i]
			p.pk.a[j][i] = t
		}
	}
}

// Scheme returns the standardized scheme name.
func (p *Kyber) Scheme() string {
	return p.Name
}
