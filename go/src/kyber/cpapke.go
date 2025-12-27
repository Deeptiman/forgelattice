package kyber

import (
	"encoding/binary"
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
				p[i] = int16(t0)
				i++
			}

			if t1 < uint16(Q) && i < len(p) {
				p[i] = int16(t1)
				i++
			}
		}
	}
	return p
}

func (p *Poly) DeriveNoiseWithEta2(seed []byte, noiseBuffer uint8) {
	const (
		mask    = uint64(0x5555555555555555)
		sumBits = 2
	)

	h := sha3.NewShake256()
	_, _ = h.Write(seed[:])
	_, _ = h.Write([]byte{noiseBuffer}) // domain-separator byte

	var buf [128]byte
	h.Read(buf[:])
	out := 0
	for i := 0; i < len(buf); i += 8 {
		// Load 64 bits
		t := binary.LittleEndian.Uint64(buf[i:])

		// Form packed sums: (a0+a1), (b0+b1), ...
		d := t & mask
		for k := uint(1); k < sumBits; k++ {
			d += (t >> k) & mask
		}

		for j := 0; j < 16 && out < len(p); j++ {
			a := int16(d & ((1 << sumBits) - 1))
			d >>= sumBits
			b := int16(d & ((1 << sumBits) - 1))
			d >>= sumBits
			p[out] = a - b
			out++
		}
	}
}

func (p *Poly) DeriveNoiseWithEta3(seed []byte, noiseBuffer uint8) {
	const (
		mask    = uint64(0x249249249249)
		sumBits = 3
	)

	// If eta = 3, these are the ground rules.
	//
	// Polynomial Size: N = 256
	// Bits per coefficient: 2*η = 6
	// Total bits: 256 x 6 = 1536
	// Total bytes: 1536 / 8 = 192
	// Coefficients per 6-byte block: 8
	// Number of blocks: 192 / 6 = 32

	// SHAKE256(seed || nonce)
	h := sha3.NewShake256()
	h.Write(seed)
	h.Write([]byte{noiseBuffer})

	// 192-bytes of entropy + 2 bytes zero padding
	var buf [192 + 2]byte
	h.Read(buf[:192]) // padding stays zero

	out := 0
	for i := 0; i < 32; i++ {
		t := binary.LittleEndian.Uint64(buf[6*i:]) // Extract 6-bytes of buffer per block.

		d := t & mask
		for k := uint(1); k < sumBits; k++ {
			d += (t >> k) & mask
		}

		// Parallel bit sum:
		for j := 0; j < 8; j++ {
			// a = a1 + a2 + a3
			a := int16(d) & 0x7
			d >>= sumBits
			// b = b1 + b2 + b3
			b := int16(d) & 0x7
			d >>= sumBits
			p[out] = a - b
			out++
		}
	}
}
