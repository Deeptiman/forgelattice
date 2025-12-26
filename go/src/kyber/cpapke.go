package kyber

import (
	"github.com/Deeptiman/forgekey/go/src/sha3"
)

// Kyber key-generation steps [PublicKey, PrivateKey]
// 1. Generate 32-bytes random seed
// 2. Expand seed with SHAKE256
// 3. Split the seed into seedA and seedS
// 4. Deterministically generate public matrix A from seedA
// 5. Sample secret vector s using CBD (Centered Binomial Distribution)
// 6. Sample noise vector e using CBD (Centered Binomial Distribution)
// 7. Compute [A * s + e (mod Q)]
// 8. Output public key (seedA, t)
// 9. Output secret key s

func (p *Params) GeneratePublicKey(rho [32]byte) PublicKey {
	// 1. Gather 32-bytes random numbers (rho).
	// 2. Shake it with 128-bit for each row & column and rho bytes.
	// 3. Apply rejection sampler for each iteration to collect 12-bits of buffer.
	// 4. Add it to the polynomial coefficients.
	// 5. Complete the loop to generate KxK matrix uniform within [0 ... Q)
	for x := 0; x < p.K; x++ {
		for y := 0; y < p.K; y++ {
			p.A[x][y].PolyUniform(&rho, byte(y), byte(x))
		}
	}
	return PublicKey{rho: rho, A: p.A}
}

func (p *Poly) PolyUniform(rho *[32]byte, x, y byte) *Poly {
	shake := sha3.NewShake128()
	_, _ = shake.Write(rho[:])
	_, _ = shake.Write([]byte{x, y})
	buf := make([]byte, 168) // max SHAKE rate block
	i := 0

	for i < N {
		shake.Read(buf[:])
		for j := 0; j < 168; j += 3 {
			xx := uint32(buf[j]) | (uint32(buf[j+1]) << 8) | (uint32(buf[j+2]) << 16)
			t0 := uint16(xx & 0xfff)
			t1 := uint16((xx >> 12) & 0xfff)

			if t0 < uint16(Q) && i < len(p) {
				p[i] = t0
				i++
			}

			if t1 < uint16(Q) && i < len(p) {
				p[i] = t1
				i++
			}
		}
	}
	return p
}
