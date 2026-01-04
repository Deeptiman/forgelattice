package kyber

import (
	"encoding/binary"
	"github.com/Deeptiman/forgekey/go/src/sha3"
)

type (
	Poly       [N]int16
	PolyVec    []Poly
	PolyMatrix []PolyVec
	Mat        PolyMatrix
)

func (p *Poly) PolyUniform(rho *[32]byte, x, y byte) {
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
}

func (p *Poly) SampleNoise(seed []byte, noiseBuffer uint8, eta int) {
	switch eta {
	case 2:
		p.GenerateSecretVectorNoiseWithEta2(seed, noiseBuffer)
	case 3:
		p.GenerateSecretVectorNoiseWithEta3(seed, noiseBuffer)
	}
}

func (p *Poly) GenerateSecretVectorNoiseWithEta2(seed []byte, noiseBuffer uint8) {
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

func (p *Poly) GenerateSecretVectorNoiseWithEta3(seed []byte, noiseBuffer uint8) {
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

func (p *Poly) MulWrapped(a, b *Poly) {
	k := 64
	for i := 0; i < N; i += 4 {
		zeta := zetas[k]
		k++

		// first pair: x² = +zeta
		t0 := MontgomeryMul(int32(a[i+1]), int32(b[i+1]))
		t0 = MontgomeryMul(int32(t0), int32(zeta))
		t0 += MontgomeryMul(int32(a[i]), int32(b[i]))

		t1 := MontgomeryMul(int32(a[i]), int32(b[i+1]))
		t1 += MontgomeryMul(int32(a[i+1]), int32(b[i]))

		p[i] += t0
		p[i+1] += t1

		// second pair: x² = -zeta
		t2 := MontgomeryMul(int32(a[i+3]), int32(b[i+3]))
		t2 = -MontgomeryMul(int32(t2), int32(zeta))
		t2 += MontgomeryMul(int32(a[i+2]), int32(b[i+2]))

		t3 := MontgomeryMul(int32(a[i+2]), int32(b[i+3]))
		t3 += MontgomeryMul(int32(a[i+3]), int32(b[i+2]))

		p[i+2] += t2
		p[i+3] += t3
	}
}

func (p *Poly) Normalize() {
	for i := 0; i < N; i++ {
		p[i] = maybeReduce(p[i])
	}
}

func (p *Poly) Zero() {
	for i := 0; i < N; i++ {
		p[i] = 0
	}
}

func (p *Poly) ToMont() {
	for i := 0; i < N; i++ {
		p[i] = ToMontgomery(int32(p[i]))
	}
}

func (p *Poly) Add(q Poly) {
	for i := 0; i < N; i++ {
		p[i] += q[i]
	}
}

func (p *Poly) Sub(q Poly) {
	for i := 0; i < N; i++ {
		p[i] -= q[i]
	}
}

func (p *Poly) Pack(buf []byte) {
	for i := 0; i < 128; i++ {
		// Two coefficients, each guaranteed < 2^12
		a := uint32(p[2*i])
		b := uint32(p[2*i+1])

		// Combine into one 24-bit word:
		// bits 0...12 = a
		// bits 12...23 = b
		w := a | (b << 12)

		// Write little-endian
		buf[3*i] = byte(w)
		buf[3*i+1] = byte(w >> 8)
		buf[3*i+2] = byte(w >> 16)
	}
}

func (p *Poly) UnPack(buf []byte) {
	for i := 0; i < 128; i++ {
		w := uint32(buf[3*i]) | uint32(buf[3*i+1])<<8 | uint32(buf[3*i+2])<<16
		p[2*i] = int16(w & 0xFFF)
		p[2*i+1] = int16((w >> 12) & 0xFFF)
	}
}
