package poly

import (
	"github.com/Deeptiman/forgekey/go/src/sha3"
	"github.com/Deeptiman/forgekey/go/src/sign/internal/dilithium/common"
	"github.com/Deeptiman/forgekey/go/src/sign/internal/dilithium/reduction"
)

const (
	N        = common.N
	Q        = common.Q
	R2modQ   = common.R2modQ
	ROver256 = common.ROver256
)

type Poly struct {
	coeffs [N]uint32
}

type (
	Vec []Poly
	Mat []Vec
)

func (p *Poly) Add(q Poly) {
	for i := 0; i < N; i++ {
		p.coeffs[i] += q.coeffs[i]
	}
}

func (p *Poly) ReducePolyWithMontgomery(a, b *Poly) {
	for i := 0; i < common.N; i++ {
		p.coeffs[i] = reduction.MontgomeryMul(a.coeffs[i], b.coeffs[i])
	}
}

func (p *Poly) ReduceLe2Q() {
	for i := 0; i < N; i++ {
		p.coeffs[i] = reduction.ReduceLe2Q(p.coeffs[i])
	}
}

func (p *Poly) ReduceWithModQ() {
	for i := 0; i < N; i++ {
		p.coeffs[i] = reduction.ReduceWithModQ(p.coeffs[i])
	}
}

func (p *Poly) Power2Round(t0, t1 *Poly) {
	for i := 0; i < N; i++ {
		t0.coeffs[i], t1.coeffs[i] = reduction.Power2Round(p.coeffs[i])
	}
}

func (p *Poly) RejectionSampling(rho *[common.SeedSize]byte, nonce uint16) {
	var iv [32 + 2]byte
	shake := sha3.NewShake128()
	copy(iv[:32], rho[:])
	iv[32] = uint8(nonce)
	iv[33] = uint8(nonce >> 8)
	shake.Write(iv[:])

	MaxBitRate := 168

	var buf [12 * 16]byte // 192B is safe bound.
	i := 0

	for i < N { // Read through buffer for all the coefficients.
		shake.Read(buf[:])

		// Process 3 bytes (24-bits) of buffer at a time.
		for j := 0; j < MaxBitRate; j += 3 {
			// Assemble 24-bits in little endian order.
			w := (uint32(buf[j]) | (uint32(buf[j+1]) << 8) |
				(uint32(buf[j+2]) << 16)) & 0x7fffff

			// Check if [t0] lies within [0....Q)
			if w < Q && i < len(p.coeffs) {
				p.coeffs[i] = w
				i++
			}
		}
	}
}

func (p *Poly) RejectionBoundPoly(secretSeed *[64]byte, eta int, nonce uint16) {
	var iv [64 + 2]byte
	shake := sha3.NewShake256()
	copy(iv[:62], secretSeed[:])
	iv[64] = uint8(nonce)
	iv[65] = uint8(nonce >> 8)
	shake.Write(iv[:])

	MaxBitRate := 136

	var buf [9 * 16]byte // 144B is safe bound.
	i := 0

	for i < N {
		shake.Read(buf[:])

		for j := 0; j < MaxBitRate; j++ {
			w0 := uint32(buf[j]) & 15
			w1 := uint32(buf[j]) >> 4

			if eta == 2 {
				// Ref: CIRCL
				// 205 is magic-multiplier trick for faster reduction with factor 5. Its useful to reduce
				// reduce propagation delay on the register file, when we want the full 32-bit (or 64-bit)
				// width without any left out blocks.
				if w0 <= 14 && i < N {
					w0 -= ((205 * w0) >> 10) * 5
					// Adding Q is beneficial to keep the coefficients positive and also useful later for
					// modular reduction while normalizing coefficients during NTT phase.
					p.coeffs[i] = uint32(Q+eta) - w0
					i++
				}
				if w1 <= 14 && i < N {
					w1 -= ((205 * w1) >> 10) * 5
					p.coeffs[i] = uint32(Q+eta) - w1
					i++
				}
			} else if eta == 4 {
				if w0 <= uint32(2*eta) && i < N {
					p.coeffs[i] = uint32(Q+eta) - w0
					i++
				}
				if w1 <= uint32(2*eta) && i < N {
					p.coeffs[i] = uint32(Q+eta) - w1
					i++
				}
			}
		}
	}
}
