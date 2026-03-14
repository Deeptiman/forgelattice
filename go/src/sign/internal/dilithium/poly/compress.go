package poly

import "github.com/Deeptiman/forgekey/go/src/sign/internal/dilithium/common"

func (p *Poly) PackPublicKeyT1(buf []byte) {
	j := 0
	for i := 0; i < common.PolyT1PackSize; i += 5 {
		// read all 8-bits
		buf[i] = byte(p.coeffs[j])
		// take all 8-bits OR with low-2bits
		buf[i+1] = byte(p.coeffs[j]>>8) | byte(p.coeffs[j+1]<<2)
		// take upper 2-bits OR with low-4-bits
		buf[i+2] = byte(p.coeffs[j+1]>>2) | byte(p.coeffs[j+2]<<4)
		// take upper 4-bits OR with low-6-bits
		buf[i+3] = byte(p.coeffs[j+2]>>4) | byte(p.coeffs[j+3]<<6)
		// take upper 2-bits
		buf[i+4] = byte(p.coeffs[j+3] >> 2)
		j += 4
	}
}
