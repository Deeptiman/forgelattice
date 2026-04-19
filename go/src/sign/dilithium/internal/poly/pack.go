package poly

import (
	"github.com/Deeptiman/forgekey/go/src/sign/dilithium/internal/common"
)

func (p *Poly) BitUnpack(buf []byte, gammaBits, polyLeGamma1Size int) {
	Gamma1 := uint32(1 << gammaBits)

	j := 0
	if gammaBits == 17 {
		for i := 0; i < polyLeGamma1Size; i += 9 {
			x0 := uint32(buf[i]) | (uint32(buf[i+1]) << 8) | (uint32(buf[i+2]&0x3) << 16)
			x1 := uint32(buf[i+2]>>2) | (uint32(buf[i+3]) << 6) | (uint32(buf[i+4]&0xf) << 14)
			x2 := uint32(buf[i+4]>>4) | (uint32(buf[i+5]) << 4) | (uint32(buf[i+6]&0x3f) << 12)
			x3 := uint32(buf[i+6]>>6) | (uint32(buf[i+7]) << 2) | (uint32(buf[i+8]) << 10)

			x0 = Gamma1 - x0
			x1 = Gamma1 - x1
			x2 = Gamma1 - x2
			x3 = Gamma1 - x3

			x0 += uint32(int32(x0)>>31) & common.Q
			x1 += uint32(int32(x1)>>31) & common.Q
			x2 += uint32(int32(x2)>>31) & common.Q
			x3 += uint32(int32(x3)>>31) & common.Q

			p.coeffs[j] = x0
			p.coeffs[j+1] = x1
			p.coeffs[j+2] = x2
			p.coeffs[j+3] = x3

			j += 4
		}
	} else if gammaBits == 19 {
		for i := 0; i < polyLeGamma1Size; i += 5 {
			p0 := uint32(buf[i]) | (uint32(buf[i+1]) << 8) | (uint32(buf[i+2]&0xf) << 16)
			p1 := uint32(buf[i+2]>>4) | (uint32(buf[i+3]) << 4) | (uint32(buf[i+4]) << 12)

			p0 = Gamma1 - p0
			p1 = Gamma1 - p1

			p0 += uint32(int32(p0)>>31) & common.Q
			p1 += uint32(int32(p1)>>31) & common.Q

			p.coeffs[j] = p0
			p.coeffs[j+1] = p1

			j += 2
		}
	}
}

func (p *Poly) BitPack(buf []byte, gammaBit, polyLeGamma1Size int) {
	Gamma1 := uint32(1 << gammaBit)

	j := 0
	if gammaBit == 17 {
		for i := 0; i < polyLeGamma1Size; i += 9 {
			x0 := Gamma1 - p.coeffs[j]
			x0 += uint32(int32(x0)>>31) & common.Q

			x1 := Gamma1 - p.coeffs[j+1]
			x1 += uint32(int32(x1)>>31) & common.Q

			x2 := Gamma1 - p.coeffs[j+2]
			x2 += uint32(int32(x2)>>31) & common.Q

			x3 := Gamma1 - p.coeffs[j+3]
			x3 += uint32(int32(x3)>>31) & common.Q

			buf[i+0] = byte(x0)
			buf[i+1] = byte(x0 >> 8)
			buf[i+2] = byte(x0>>16) | byte(x1<<2)
			buf[i+3] = byte(x1 >> 6)
			buf[i+4] = byte(x1>>14) | byte(x2<<4)
			buf[i+5] = byte(x2 >> 4)
			buf[i+6] = byte(x2>>12) | byte(x3<<6)
			buf[i+7] = byte(x3 >> 2)
			buf[i+8] = byte(x3 >> 10)

			j += 4
		}
	} else if gammaBit == 19 {
		for i := 0; i < polyLeGamma1Size; i += 5 {
			// Coefficients are in [0, γ₁] ∪ (Q-γ₁, Q)
			p0 := Gamma1 - p.coeffs[j]
			p0 += uint32(int32(p0)>>31) & common.Q
			p1 := Gamma1 - p.coeffs[j+1]
			p1 += uint32(int32(p1)>>31) & common.Q

			buf[i+0] = byte(p0)
			buf[i+1] = byte(p0 >> 8)
			buf[i+2] = byte(p0>>16) | byte(p1<<4)
			buf[i+3] = byte(p1 >> 4)
			buf[i+4] = byte(p1 >> 12)

			j += 2
		}
	}
}

func (p *Poly) PackPublicKeyT1(buf []byte) {
	j := 0
	for i := 0; i < common.PolyT1PackSize; i += 5 {
		// read all 8-bits
		buf[i] = byte(p.coeffs[j])
		// take all 8-bits XOR with low-2bits
		buf[i+1] = byte(p.coeffs[j]>>8) | byte(p.coeffs[j+1]<<2)
		// take upper 6-bits XOR with low-4-bits
		buf[i+2] = byte(p.coeffs[j+1]>>6) | byte(p.coeffs[j+2]<<4)
		// take upper 4-bits XOR with low-6-bits
		buf[i+3] = byte(p.coeffs[j+2]>>4) | byte(p.coeffs[j+3]<<6)
		// take upper 2-bits
		buf[i+4] = byte(p.coeffs[j+3] >> 2)
		j += 4
	}
}

func (p *Poly) Encode(packSize, gamma1Bits int, buf []byte) {
	if gamma1Bits == 19 {
		p.PackLe16(buf)
	} else if gamma1Bits == 17 {
		j := 0
		for i := 0; i < packSize; i += 3 {
			buf[i] = byte(p.coeffs[j]) | byte(p.coeffs[j+1]<<6)
			buf[i+1] = byte(p.coeffs[j+1]>>2) | byte(p.coeffs[j+2]<<4)
			buf[i+2] = byte(p.coeffs[j+2]>>4) | byte(p.coeffs[j+3]<<2)
			j += 4
		}
	}
}

func (p *Poly) PackLe16(buf []byte) {
	// early bounds so we don't have to in assembly code
	// compiler may inline this func, so it may remove the bounds check
	_ = buf[common.PolyLe16Size-1]

	polyPackLe16ARM64(p, &buf[0])
}
