package poly

import (
	"github.com/Deeptiman/forgelattice/crypto/kem/internal/common"
	"github.com/Deeptiman/forgelattice/crypto/kem/internal/reduction"
	"github.com/Deeptiman/forgelattice/crypto/sha3"
)

const (
	N          = common.N
	Q          = common.Q
	SeedSize   = common.SeedSize
	MaxBitRate = common.MaxBitRate
)

type Poly struct {
	coeffs [N]int16
}

type (
	Vec    []Poly
	Matrix []Vec
	Mat    Matrix
)

func WithCoeffs(coeffs [N]int16) Poly {
	return Poly{coeffs: coeffs}
}

func (p *Poly) RejectionSampling(rho *[SeedSize]byte, x, y byte) {
	// Initialize SHAKE128 as an extendable-output PRF.
	// The seed rho with x, y indices uniquely determines the output stream.
	shake := sha3.NewShake128()
	_, _ = shake.Write(rho[:])
	_, _ = shake.Write([]byte{x, y})

	buf := make([]byte, MaxBitRate) // max SHAKE rate block
	i := 0

	for i < N { // Read through buffer for all the coefficients.
		shake.Read(buf[:])

		// Process 3 bytes (24-bits) of buffer at a time.
		for j := 0; j < MaxBitRate; j += 3 {
			// Assemble 24-bits in little endian order.
			w := uint32(buf[j]) |
				(uint32(buf[j+1]) << 8) |
				(uint32(buf[j+2]) << 16)

			// Split the 24-bit word into two 12-bits rejection sampling candidate.
			t0 := uint16(w & 0xfff)
			t1 := uint16((w >> 12) & 0xfff)

			// Check if [t0] lies within [0....Q)
			if t0 < uint16(Q) && i < len(p.coeffs) {
				p.coeffs[i] = int16(t0)
				i++
			}

			// Check if [t1] lies within [0....Q)
			if t1 < uint16(Q) && i < len(p.coeffs) {
				p.coeffs[i] = int16(t1)
				i++
			}
		}
	}
}

func (p *Poly) SampleNoise(seed []byte, noiseBuffer uint8, eta int) {
	switch eta {
	case 2:
		p.GenerateSecretVectorNoiseWithEta2(seed, noiseBuffer)
	case 3:
		p.GenerateSecretVectorNoiseWithEta3(seed, noiseBuffer)
	}
}

func (p *Poly) Reduce() {
	for i := 0; i < N; i++ {
		p.coeffs[i] = reduction.Maybe(p.coeffs[i])
	}
}

func (p *Poly) Zero() {
	for i := 0; i < N; i++ {
		p.coeffs[i] = 0
	}
}

func (p *Poly) ToMont() {
	for i := 0; i < N; i++ {
		p.coeffs[i] = reduction.ToMontgomery(int32(p.coeffs[i]))
	}
}

func (p *Poly) Add(q Poly) {
	for i := 0; i < N; i++ {
		p.coeffs[i] += q.coeffs[i]
	}
}

func (p *Poly) Sub(q Poly) {
	for i := 0; i < N; i++ {
		p.coeffs[i] -= q.coeffs[i]
	}
}
