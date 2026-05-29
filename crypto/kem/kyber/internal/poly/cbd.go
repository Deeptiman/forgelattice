package poly

import (
	"encoding/binary"
	"github.com/Deeptiman/forgelattice/crypto/sha3"
)

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
	l := 0
	for i := 0; i < len(buf); i += 8 {
		t := binary.LittleEndian.Uint64(buf[i:]) // Extract 8-bytes of buffer per block.

		// Form packed sums: (a0+a1), (b0+b1), ...
		d := t & mask
		for k := uint(1); k < sumBits; k++ {
			d += (t >> k) & mask
		}

		for j := 0; j < 16 && l < len(p.coeffs); j++ {
			a := int16(d & ((1 << sumBits) - 1))
			d >>= sumBits
			b := int16(d & ((1 << sumBits) - 1))
			d >>= sumBits
			p.coeffs[l] = a - b
			l++
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
	_, _ = h.Write(seed)
	_, _ = h.Write([]byte{noiseBuffer})

	// 192-bytes of entropy + 2 bytes zero padding
	var buf [192 + 2]byte
	h.Read(buf[:192]) // padding stays zero

	l := 0
	for i := 0; i < N/8; i++ {
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
			p.coeffs[l] = a - b
			l++
		}
	}
}
