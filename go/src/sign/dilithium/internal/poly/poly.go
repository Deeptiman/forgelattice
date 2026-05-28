package poly

import (
	"encoding/binary"
	"github.com/Deeptiman/forgelattice/go/src/sha3"
	"github.com/Deeptiman/forgelattice/go/src/sign/dilithium/internal/common"
	"github.com/Deeptiman/forgelattice/go/src/sign/dilithium/internal/reduction"
)

type Poly struct {
	coeffs [common.N]uint32
}

type (
	Vec []Poly
	Mat []Vec
)

func New(coeffs [common.N]uint32) Poly {
	return Poly{coeffs: coeffs}
}

func (p *Poly) Add(a, b *Poly) {
	polyAddARM64(p, a, b)
}

func (p *Poly) Sub(a, b *Poly) {
	polySubARM64(p, a, b)
}

func (p *Poly) MulHatGeneric(a, b *Poly) {
	for i := 0; i < common.N; i++ {
		p.coeffs[i] = montReduceLe2Q(uint64(a.coeffs[i]) * uint64(b.coeffs[i]))
	}
}

func (p *Poly) DotWithMontgomery(a, b *Poly) {
	for i := 0; i < common.N; i++ {
		p.coeffs[i] = reduction.Le2Q(uint64(a.coeffs[i]) * uint64(b.coeffs[i]))
	}
}

func (p *Poly) Le2QUsingCIRCL() {
	for i := 0; i < common.N; i++ {
		p.coeffs[i] = reduction.Le2QUsingCIRCL(p.coeffs[i])
	}
}

func (p *Poly) ReduceLe2QModQ() {
	for i := 0; i < common.N; i++ {
		p.coeffs[i] = reduction.Le2QModQ(p.coeffs[i])
	}
}

func (p *Poly) ReduceWithModQ() {
	for i := 0; i < common.N; i++ {
		p.coeffs[i] = reduction.ReduceWithModQ(p.coeffs[i])
	}
}

func (p *Poly) MakeHint(Gamma2 int, z, r1 *Poly) int {
	hintCount := 0
	for i := 0; i < common.N; i++ {
		h := makeHint(uint32(Gamma2), z.coeffs[i], r1.coeffs[i])
		hintCount += h
		p.coeffs[i] = uint32(h)
	}
	return hintCount
}

func makeHint(Gamma2, z0, r1 uint32) int {
	if z0 <= Gamma2 || z0 > common.Q-Gamma2 || (z0 == common.Q-Gamma2 && r1 == 0) {
		return 0
	}
	return 1
}

func (p *Poly) PackHint(buf []byte, index uint8) uint8 {
	for i := 0; i < common.N; i++ {
		if p.coeffs[i] != 0 {
			buf[index] = uint8(i)
			index++
		}
	}
	return index
}

func (p *Poly) ExceedsBound(bound uint32) bool {
	for i := 0; i < common.N; i++ {
		x := int32((common.Q-1)/2) - int32(p.coeffs[i])
		x ^= x >> 31
		x = int32((common.Q-1)/2) - x
		if uint32(x) >= bound {
			return true
		}
	}
	return false
}

func (p *Poly) DeriveUniformLeGamma1(gamma1Bits, polyLeGamma1Size int, seed *[64]byte, nonce uint16) {
	buf := make([]byte, polyLeGamma1Size)
	h := sha3.NewShake256()
	var iv [66]byte
	copy(iv[:64], seed[:])
	iv[64] = uint8(nonce)
	iv[65] = uint8(nonce >> 8)
	_, _ = h.Write(iv[:])
	h.Read(buf[:])
	p.BitUnpack(buf[:], gamma1Bits, polyLeGamma1Size)
}

func (p *Poly) SampleInBall(tau int, seed []byte) {
	var buf [136]byte

	h := sha3.NewShake256()
	_, _ = h.Write(seed[:])
	h.Read(buf[:])

	sign := binary.LittleEndian.Uint64(buf[:])

	offset := 8
	*p = Poly{}
	for i := uint16(common.N - tau); i < common.N; i++ {
		var b uint16
		for {
			if offset >= 136 {
				h.Read(buf[:])
				offset = 0
			}

			b = uint16(buf[offset])
			offset++

			if b <= i {
				break
			}
		}

		p.coeffs[i] = p.coeffs[b]
		p.coeffs[b] = 1
		p.coeffs[b] ^= uint32((-(sign & 1)) & (1 | (common.Q - 1)))
		sign >>= 1
	}
}

func (p *Poly) Power2Round(t0, t1 *Poly) {
	for i := 0; i < common.N; i++ {
		t0.coeffs[i], t1.coeffs[i] = reduction.Power2Round(p.coeffs[i])
	}
}

func (p *Poly) MultiplyBy2ToD(q *Poly) {
	//for i := 0; i < common.N; i++ {
	//	p.coeffs[i] += q.coeffs[i] * (1 << common.D)
	//}
	polyMulBy2toDARM64(p, q)
}

func (m Mat) ExpandA(seed [common.SeedSize]byte, K, L int) {
	for i := 0; i < K; i++ {
		for j := 0; j < L; j++ {
			m[i][j].RejectionSampling(&seed, uint16((i<<8)+j))
		}
	}
}

func (p *Poly) RejectionSampling(seed *[common.SeedSize]byte, nonce uint16) {
	var iv [32 + 2]byte
	shake := sha3.NewShake128()
	copy(iv[:32], seed[:])
	iv[32] = uint8(nonce)
	iv[33] = uint8(nonce >> 8)
	_, _ = shake.Write(iv[:])

	MaxBitRate := 168

	var buf [12 * 16]byte // 192B is safe bound.
	i := 0

	for i < common.N { // Read through buffer for all the coefficients.
		shake.Read(buf[:MaxBitRate])

		// Process 3 bytes (24-bits) of buffer at a time.
		for j := 0; j < MaxBitRate && i < common.N; j += 3 {
			// Assemble 24-bits in little endian order.
			w := (uint32(buf[j]) | (uint32(buf[j+1]) << 8) |
				(uint32(buf[j+2]) << 16)) & 0x7fffff

			// Check if [t0] lies within [0....Q)
			if w < common.Q && i < len(p.coeffs) {
				p.coeffs[i] = w
				i++
			}
		}
	}
}

func (p *Poly) RejectionBoundPoly(secretSeed *[64]byte, eta int, nonce uint16) {
	var iv [64 + 2]byte
	shake := sha3.NewShake256()
	copy(iv[:64], secretSeed[:])
	iv[64] = uint8(nonce)
	iv[65] = uint8(nonce >> 8)
	_, _ = shake.Write(iv[:])

	MaxBitRate := 136

	var buf [9 * 16]byte // 144B is safe bound.
	i := 0

	for i < common.N {
		shake.Read(buf[:MaxBitRate])

		for j := 0; j < MaxBitRate && i < common.N; j++ {
			w0 := uint32(buf[j]) & 15
			w1 := uint32(buf[j]) >> 4

			if eta == 2 {
				// Ref: CIRCL
				// 205 is magic-multiplier trick for faster reduction with factor 5. Its useful to reduce
				// reduce propagation delay on the register file, when we want the full 32-bit (or 64-bit)
				// width without any left out blocks.
				if w0 <= 14 {
					w0 -= ((205 * w0) >> 10) * 5
					// Adding Q is beneficial to keep the coefficients positive and also useful later for
					// modular reduction while normalizing coefficients during NTT phase.
					p.coeffs[i] = uint32(common.Q+eta) - w0
					i++
				}
				if w1 <= 14 && i < common.N {
					w1 -= ((205 * w1) >> 10) * 5
					p.coeffs[i] = uint32(common.Q+eta) - w1
					i++
				}
			} else if eta == 4 {
				if w0 <= uint32(2*eta) {
					p.coeffs[i] = uint32(common.Q+eta) - w0
					i++
				}
				if w1 <= uint32(2*eta) && i < common.N {
					p.coeffs[i] = uint32(common.Q+eta) - w1
					i++
				}
			}
		}
	}
}

func (p *Poly) AssignHint(index uint8, buf []byte) {
	p.coeffs[buf[index]] = 1
}

func (p *Poly) UseHint(gamma2 int, w0, w1 *Poly) {
	for i := 0; i < common.N; i++ {
		if p.coeffs[i] == 0 {
			continue
		}
		if gamma2 == 261888 {
			if w0.coeffs[i] > common.Q {
				w1.coeffs[i] = (w1.coeffs[i] + 1) & 15
			} else {
				w1.coeffs[i] = (w1.coeffs[i] - 1) & 15
			}
		} else if gamma2 == 95232 {
			if w0.coeffs[i] > common.Q {
				if w1.coeffs[i] == 43 {
					w1.coeffs[i] = 0
				} else {
					w1.coeffs[i] = w1.coeffs[i] + 1
				}
			} else {
				if w1.coeffs[i] == 0 {
					w1.coeffs[i] = 43
				} else {
					w1.coeffs[i] = w1.coeffs[i] - 1
				}
			}
		}
	}
}

func (p *Poly) Decompose(alpha int) (Poly, Poly) {
	var p1, p2 Poly
	for i := 0; i < common.N; i++ {
		p1.coeffs[i], p2.coeffs[i] = decompose(alpha, p.coeffs[i])
	}
	return p1, p2
}

// Ref: CIRCL decompose with Rounding techniques.
func decompose(alpha int, coeff uint32) (a0, a1 uint32) {
	// For alpha = 190464
	//
	// --> 2²⁴ / 190464 = 88
	// But keeping 128 as base factor will provide CPU cycle processing advantages.
	a1 = (coeff + 127) >> 7
	if alpha == 190464 {
		// 11275 is magic-multiplier for faster computation.
		// 190464/128 = 1488
		// 2²⁴/1488 = 11275
		//
		a1 = ((a1 * 11275) + 1<<23) >> 24
		// Q = 8380417/190464 = 44
		// Check for the overflow: a1 = (q-1)/α = 44
		a1 ^= uint32(int32(43-a1)>>31) & a1
	} else if alpha == 523776 {
		// 1025 is magic-multiplier for faster computation.
		// 523776/128 = 4092
		// 2²²/4092 = 1025
		//
		a1 = ((a1 * 1025) + 1<<21) >> 22
		// Q = 8380417/523776 = 16
		// Check for the overflow: a1 = (q-1)/α = 16
		a1 &= 15
	}
	a0 = coeff - a1*uint32(alpha)
	a0 += uint32(int32(a0-(common.Q-1)/2)>>31) & common.Q
	return
}

func (p *Poly) PackLeqEta(buf []byte, Eta uint32, DoubleEtaBits, PolyLeqEtaSize int) {
	if DoubleEtaBits == 4 {
		j := 0
		for i := 0; i < PolyLeqEtaSize; i++ {
			buf[i] = byte(common.Q+Eta-p.coeffs[j]) | byte(common.Q+Eta-p.coeffs[j+1])<<4
			j += 2
		}
	} else if DoubleEtaBits == 3 {
		j := 0
		for i := 0; i < PolyLeqEtaSize; i += 3 {
			buf[i] = byte(common.Q+Eta-p.coeffs[j]) | (byte(common.Q+Eta-p.coeffs[j+1]) << 3) |
				(byte(common.Q+Eta-p.coeffs[j+2]) << 6)
			buf[i+1] = (byte(common.Q+Eta-p.coeffs[j+2]) >> 2) | (byte(common.Q+Eta-p.coeffs[j+3]) << 1) |
				(byte(common.Q+Eta-p.coeffs[j+4]) << 4) | (byte(common.Q+Eta-p.coeffs[j+5]) << 7)
			buf[i+2] = (byte(common.Q+Eta-p.coeffs[j+5]) >> 1) | (byte(common.Q+Eta-p.coeffs[j+6]) << 2) |
				(byte(common.Q+Eta-p.coeffs[j+7]) << 5)
			j += 8
		}
	}
}

func (p *Poly) UnpackLeqEta(buf []byte, Eta uint32, DoubleEtaBits, PolyLeqEtaSize int) {
	if DoubleEtaBits == 4 {
		j := 0
		for i := 0; i < PolyLeqEtaSize; i++ {
			p.coeffs[j] = common.Q + Eta - uint32(buf[i]&15)
			p.coeffs[j+1] = common.Q + Eta - uint32(buf[i]>>4)
			j += 2
		}
	} else if DoubleEtaBits == 3 {
		j := 0
		for i := 0; i < PolyLeqEtaSize; i += 3 {
			p.coeffs[j] = common.Q + Eta - uint32(buf[i]&7)
			p.coeffs[j+1] = common.Q + Eta - uint32((buf[i]>>3)&7)
			p.coeffs[j+2] = common.Q + Eta - uint32((buf[i]>>6)|((buf[i+1]<<2)&7))
			p.coeffs[j+3] = common.Q + Eta - uint32((buf[i+1]>>1)&7)
			p.coeffs[j+4] = common.Q + Eta - uint32((buf[i+1]>>4)&7)
			p.coeffs[j+5] = common.Q + Eta - uint32((buf[i+1]>>7)|((buf[i+2]<<1)&7))
			p.coeffs[j+6] = common.Q + Eta - uint32((buf[i+2]>>2)&7)
			p.coeffs[j+7] = common.Q + Eta - uint32((buf[i+2]>>5)&7)
			j += 8
		}
	}
}

func (p *Poly) PackT0(buf []byte) {
	j := 0
	for i := 0; i < common.PolyT0PackSize; i += 13 {
		p0 := common.Q + (1 << (common.D - 1)) - p.coeffs[j]
		p1 := common.Q + (1 << (common.D - 1)) - p.coeffs[j+1]
		p2 := common.Q + (1 << (common.D - 1)) - p.coeffs[j+2]
		p3 := common.Q + (1 << (common.D - 1)) - p.coeffs[j+3]
		p4 := common.Q + (1 << (common.D - 1)) - p.coeffs[j+4]
		p5 := common.Q + (1 << (common.D - 1)) - p.coeffs[j+5]
		p6 := common.Q + (1 << (common.D - 1)) - p.coeffs[j+6]
		p7 := common.Q + (1 << (common.D - 1)) - p.coeffs[j+7]

		buf[i] = byte(p0 >> 0)
		buf[i+1] = byte(p0>>8) | byte(p1<<5)
		buf[i+2] = byte(p1 >> 3)
		buf[i+3] = byte(p1>>11) | byte(p2<<2)
		buf[i+4] = byte(p2>>6) | byte(p3<<7)
		buf[i+5] = byte(p3 >> 1)
		buf[i+6] = byte(p3>>9) | byte(p4<<4)
		buf[i+7] = byte(p4 >> 4)
		buf[i+8] = byte(p4>>12) | byte(p5<<1)
		buf[i+9] = byte(p5>>7) | byte(p6<<6)
		buf[i+10] = byte(p6 >> 2)
		buf[i+11] = byte(p6>>10) | byte(p7<<3)
		buf[i+12] = byte(p7 >> 5)
		j += 8
	}
}

func (p *Poly) UnpackT0(buf []byte) {
	j := 0
	for i := 0; i < common.PolyT0PackSize; i += 13 {
		p.coeffs[j] = common.Q + (1 << (common.D - 1)) - ((uint32(buf[i]) |
			(uint32(buf[i+1]) << 8)) & 0x1fff)
		p.coeffs[j+1] = common.Q + (1 << (common.D - 1)) - (((uint32(buf[i+1]) >> 5) |
			(uint32(buf[i+2]) << 3) | (uint32(buf[i+3]) << 11)) & 0x1fff)
		p.coeffs[j+2] = common.Q + (1 << (common.D - 1)) - (((uint32(buf[i+3]) >> 2) |
			(uint32(buf[i+4]) << 6)) & 0x1fff)
		p.coeffs[j+3] = common.Q + (1 << (common.D - 1)) - (((uint32(buf[i+4]) >> 7) |
			(uint32(buf[i+5]) << 1) | (uint32(buf[i+6]) << 9)) & 0x1fff)
		p.coeffs[j+4] = common.Q + (1 << (common.D - 1)) - (((uint32(buf[i+6]) >> 4) |
			(uint32(buf[i+7]) << 4) | (uint32(buf[i+8]) << 12)) & 0x1fff)
		p.coeffs[j+5] = common.Q + (1 << (common.D - 1)) - (((uint32(buf[i+8]) >> 1) |
			(uint32(buf[i+9]) << 7)) & 0x1fff)
		p.coeffs[j+6] = common.Q + (1 << (common.D - 1)) - (((uint32(buf[i+9]) >> 6) |
			(uint32(buf[i+10]) << 2) | (uint32(buf[i+11]) << 10)) & 0x1fff)
		p.coeffs[j+7] = common.Q + (1 << (common.D - 1)) - ((uint32(buf[i+11]) >> 3) |
			(uint32(buf[i+12]) << 5))
		j += 8
	}
}

func (p *Poly) PackT1(buf []byte) {
	j := 0
	for i := 0; i < common.PolyT1PackSize; i += 5 {
		buf[i] = byte(p.coeffs[j])
		buf[i+1] = byte(p.coeffs[j]>>8) | byte(p.coeffs[j+1]<<2)
		buf[i+2] = byte(p.coeffs[j+1]>>6) | byte(p.coeffs[j+2]<<4)
		buf[i+3] = byte(p.coeffs[j+2]>>4) | byte(p.coeffs[j+3]<<6)
		buf[i+4] = byte(p.coeffs[j+3] >> 2)
		j += 4
	}
}

func (p *Poly) UnpackT1(buf []byte) {
	j := 0
	p.coeffs = [common.N]uint32{}
	for i := 0; i < common.PolyT1PackSize; i += 5 {
		p.coeffs[j] = (uint32(buf[i]) | (uint32(buf[i+1]) << 8)) & 0x3ff
		p.coeffs[j+1] = (uint32(buf[i+1]>>2) | (uint32(buf[i+2]) << 6)) & 0x3ff
		p.coeffs[j+2] = (uint32(buf[i+2]>>4) | (uint32(buf[i+3]) << 4)) & 0x3ff
		p.coeffs[j+3] = (uint32(buf[i+3]>>6) | (uint32(buf[i+4]) << 2)) & 0x3ff
		j += 4
	}
}

func (p *Poly) Accumulator(q *Poly) uint32 {
	acc := uint32(0)
	for j := 0; j < common.N; j++ {
		acc |= p.coeffs[j] ^ q.coeffs[j]
	}
	return acc
}
