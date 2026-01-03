package kyber

type CompressParams struct {
	A uint64
	E uint
}

func compressedPolySize(d int) int {
	switch d {
	case 4:
		return 128
	case 5:
		return 160
	case 10:
		return 320
	case 11:
		return 352
	default:
		panic("unsupported d")
	}
}

func compressParams(d int) CompressParams {
	switch d {
	case 4, 5:
		return CompressParams{A: 20159, E: 26}
	case 10, 11:
		return CompressParams{A: 2580335, E: 33}
	default:
		panic("unsupported d")
	}
}

func (p *Poly) CompressD4(ct []byte) {
	idx := 0
	for i := 0; i < N/8; i++ {
		var t [8]uint16
		for j := 0; j < 8; j++ {
			t[j] = CompressCoeff(p[8*i+j], 4)
		}
		ct[idx] = byte(t[0]) | byte(t[1]<<4)
		ct[idx+1] = byte(t[2]) | byte(t[3]<<4)
		ct[idx+2] = byte(t[4]) | byte(t[5]<<4)
		ct[idx+3] = byte(t[6]) | byte(t[7]<<4)

		idx += 4
	}
}

func (p *Poly) DecompressD4(ct []byte) {
	idx := 0
	for i := 0; i < N/8; i++ {
		b0 := ct[idx]
		b1 := ct[idx+1]
		b2 := ct[idx+2]
		b3 := ct[idx+3]

		p[8*i] = DecompressCoeff(uint16(b0&0x0f), 4)
		p[8*i+1] = DecompressCoeff(uint16(b0>>4), 4)
		p[8*i+2] = DecompressCoeff(uint16(b1&0x0f), 4)
		p[8*i+3] = DecompressCoeff(uint16(b1>>4), 4)
		p[8*i+4] = DecompressCoeff(uint16(b2&0x0f), 4)
		p[8*i+5] = DecompressCoeff(uint16(b2>>4), 4)
		p[8*i+6] = DecompressCoeff(uint16(b3&0x0f), 4)
		p[8*i+7] = DecompressCoeff(uint16(b3>>4), 4)

		idx += 4
	}
}

func (p *Poly) CompressD5(ct []byte) {
	idx := 0
	var t [8]uint16
	for i := 0; i < N/8; i++ {
		for j := 0; j < 8; j++ {
			t[j] = uint16((((uint32(p[8*i+j])<<5)+uint32(Q)/2)*20159)>>26) & ((1 << 5) - 1)
		}

		ct[idx+0] = byte(t[0]) | byte(t[1]<<5)
		ct[idx+1] = byte(t[1]>>3) | byte(t[2]<<2) | byte(t[3]<<7)
		ct[idx+2] = byte(t[3]>>1) | byte(t[4]<<4)
		ct[idx+3] = byte(t[4]>>4) | byte(t[5]<<1) | byte(t[6]<<6)
		ct[idx+4] = byte(t[6]>>2) | byte(t[7]<<3)

		idx += 5
	}
}

func (p *Poly) DecompressD5(m []byte) {
	idx := 0
	var t [8]uint16
	for i := 0; i < N/8; i++ {
		t[0] = uint16(m[idx])
		t[1] = (uint16(m[idx]) >> 5) | (uint16(m[idx+1] << 3))
		t[2] = uint16(m[idx+1]) >> 2
		t[3] = (uint16(m[idx+1]) >> 7) | (uint16(m[idx+2] << 1))
		t[4] = (uint16(m[idx+2]) >> 4) | (uint16(m[idx+3] << 4))
		t[5] = uint16(m[idx+3]) >> 1
		t[6] = (uint16(m[idx+3]) >> 6) | (uint16(m[idx+4] << 2))
		t[7] = uint16(m[idx+4]) >> 3

		for j := 0; j < 8; j++ {
			p[8*i+j] = int16(((1 << 4) + uint32(t[j]&((1<<5)-1))*Q) >> 5)
		}

		idx += 5
	}
}

func (p *Poly) CompressD10(ct []byte) {
	idx := 0
	for i := 0; i < N/4; i++ {
		var t [4]uint16
		for j := 0; j < 4; j++ {
			t[j] = CompressCoeff(p[4*i+j], 10)
		}

		ct[idx+0] = byte(t[0])
		ct[idx+1] = byte(t[0]>>8) | byte(t[1]<<2)
		ct[idx+2] = byte(t[1]>>6) | byte(t[2]<<4)
		ct[idx+3] = byte(t[2]>>4) | byte(t[3]<<6)
		ct[idx+4] = byte(t[3] >> 2)

		idx += 5
	}
}

func (p *Poly) DecompressD10(ct []byte) {
	idx := 0
	for i := 0; i < N/4; i++ {
		t0 := uint16(ct[idx+0]) | (uint16(ct[idx+1]) << 8)
		t1 := (uint16(ct[idx+1]) >> 2) | (uint16(ct[idx+2]) << 6)
		t2 := (uint16(ct[idx+2]) >> 4) | (uint16(ct[idx+3]) << 4)
		t3 := (uint16(ct[idx+3]) >> 6) | (uint16(ct[idx+4]) << 2)

		p[4*i+0] = DecompressCoeff(t0&0x3ff, 10)
		p[4*i+1] = DecompressCoeff(t1&0x3ff, 10)
		p[4*i+2] = DecompressCoeff(t2&0x3ff, 10)
		p[4*i+3] = DecompressCoeff(t3&0x3ff, 10)

		idx += 5
	}
}

func (p *Poly) CompressD11(ct []byte) {
	idx := 0
	var t [8]uint16
	for i := 0; i < N/8; i++ {
		for j := 0; j < 8; j++ {
			t[j] = uint16((uint64((uint32(p[8*i+j])<<11)+uint32(Q)/2)*
				2580335)>>33) & ((1 << 11) - 1)
		}

		ct[idx+0] = byte(t[0])
		ct[idx+1] = byte(t[0]>>8) | byte(t[1]<<3)
		ct[idx+2] = byte(t[1]>>5) | byte(t[2]<<6)
		ct[idx+3] = byte(t[2] >> 2)
		ct[idx+4] = byte(t[2]>>10) | byte(t[3]<<1)
		ct[idx+5] = byte(t[3]>>7) | byte(t[4]<<4)
		ct[idx+6] = byte(t[4]>>4) | byte(t[5]<<7)
		ct[idx+7] = byte(t[5] >> 1)
		ct[idx+8] = byte(t[5]>>9) | byte(t[6]<<2)
		ct[idx+9] = byte(t[6]>>6) | byte(t[7]<<5)
		ct[idx+10] = byte(t[7] >> 3)

		idx += 11
	}
}

func (p *Poly) DecompressD11(ct []byte) {
	idx := 0
	var t [8]uint16
	for i := 0; i < N/8; i++ {
		t[0] = uint16(ct[idx+0]) | (uint16(ct[idx+1]) << 8)
		t[1] = (uint16(ct[idx+1]) >> 3) | (uint16(ct[idx+2]) << 5)
		t[2] = (uint16(ct[idx+2]) >> 6) | (uint16(ct[idx+3]) << 2) | (uint16(ct[idx+4]) << 10)
		t[3] = (uint16(ct[idx+4]) >> 1) | (uint16(ct[idx+5]) << 7)
		t[4] = (uint16(ct[idx+5]) >> 4) | (uint16(ct[idx+6]) << 4)
		t[5] = (uint16(ct[idx+6]) >> 7) | (uint16(ct[idx+7]) << 1) | (uint16(ct[idx+8]) << 9)
		t[6] = (uint16(ct[idx+8]) >> 2) | (uint16(ct[idx+9]) << 6)
		t[7] = (uint16(ct[idx+9]) >> 5) | (uint16(ct[idx+10]) << 3)

		for j := 0; j < 8; j++ {
			p[8*i+j] = int16(((1 << 10) +
				uint32(t[j]&((1<<11)-1))*Q) >> 11)
		}

		idx += 11
	}
}

func CompressCoeff(x int16, d int) uint16 {
	p := compressParams(d)
	// Fixed-point approximation of:
	// floor((x * 2^d + Q/2) / Q)
	return uint16((uint64((uint32(x)<<d)+uint32(Q)/2)*p.A)>>p.E) & ((1 << d) - 1)
}

func DecompressCoeff(t uint16, d int) int16 {
	switch d {
	case 5:
		return int16(((1 << 4) + uint32(t&((1<<5)-1))*Q) >> 5)
	}
	return int16((uint32(t)*Q + ((1 << d) - 1)) >> d)
}

func (p *Poly) Compress(ct []byte, d int) {
	switch d {
	case 4:
		p.CompressD4(ct)
	case 5:
		p.CompressD5(ct)
	case 10:
		p.CompressD10(ct)
	case 11:
		p.CompressD11(ct)
	default:
		panic("unsupported d")
	}
}

func (p *Poly) Decompress(ct []byte, d int) {
	switch d {
	case 4:
		p.DecompressD4(ct)
	case 5:
		p.DecompressD5(ct)
	case 10:
		p.DecompressD10(ct)
	case 11:
		p.DecompressD11(ct)
	default:
		panic("unsupported d")
	}
}

func (p *Poly) CompressMessage(m []byte) {
	q := int16(Q)
	low := (q + 2) / 4
	high := (3*q + 2) / 4
	for i := 0; i < 32; i++ {
		var b byte
		for j := 0; j < 8; j++ {
			t := p[8*i+j]
			if t > low && t < high {
				b |= 1 << j
			}
			m[i] = b
		}
	}
}

func (p *Poly) DecompressMessage(m []byte) {
	for i := 0; i < 32; i++ {
		for j := 0; j < 8; j++ {
			bit := (m[i] >> j) & 1
			p[8*i+j] = -int16(bit) & ((int16(Q) + 1) / 2)
		}
	}
}

func (p *Poly) EncodeMessage(msg []byte) {
	for i := 0; i < N; i++ {
		bit := (msg[i>>3] >> (i & 7)) & 1
		if bit == 1 {
			p[i] = int16(Q / 2)
		} else {
			p[i] = 0
		}
	}
}

func (p *Poly) DecodeMessage(msg [32]byte) {
	for i := 0; i < N; i++ {
		if p[i] > int16(Q/4) && p[i] < int16(3*Q/4) {
			msg[i>>3] |= 1 << (i & 7)
		}
	}
}

func (p *Poly) DecompressTo(m []byte, d int) {
	// Decompress_q(x, d) = ⌈(q/2ᵈ)x⌋
	//                    = ⌊(q/2ᵈ)x+½⌋
	//                    = ⌊(qx + 2ᵈ⁻¹)/2ᵈ⌋
	//                    = (qx + (1<<(d-1))) >> d
	switch d {
	case 4:
		for i := 0; i < N/2; i++ {
			p[2*i] = int16(((1 << 3) + uint32(m[i]&15)*uint32(Q)) >> 4)
			p[2*i+1] = int16(((1 << 3) + uint32(m[i]>>4)*uint32(Q)) >> 4)
		}
	case 5:
		var t [8]uint16
		idx := 0
		for i := 0; i < N/8; i++ {
			t[0] = uint16(m[idx])
			t[1] = (uint16(m[idx]) >> 5) | (uint16(m[idx+1] << 3))
			t[2] = uint16(m[idx+1]) >> 2
			t[3] = (uint16(m[idx+1]) >> 7) | (uint16(m[idx+2] << 1))
			t[4] = (uint16(m[idx+2]) >> 4) | (uint16(m[idx+3] << 4))
			t[5] = uint16(m[idx+3]) >> 1
			t[6] = (uint16(m[idx+3]) >> 6) | (uint16(m[idx+4] << 2))
			t[7] = uint16(m[idx+4]) >> 3

			for j := 0; j < 8; j++ {
				p[8*i+j] = int16(((1 << 4) +
					uint32(t[j]&((1<<5)-1))*uint32(Q)) >> 5)
			}

			idx += 5
		}

	case 10:
		var t [4]uint16
		idx := 0
		for i := 0; i < N/4; i++ {
			t[0] = uint16(m[idx]) | (uint16(m[idx+1]) << 8)
			t[1] = (uint16(m[idx+1]) >> 2) | (uint16(m[idx+2]) << 6)
			t[2] = (uint16(m[idx+2]) >> 4) | (uint16(m[idx+3]) << 4)
			t[3] = (uint16(m[idx+3]) >> 6) | (uint16(m[idx+4]) << 2)

			for j := 0; j < 4; j++ {
				p[4*i+j] = int16(((1 << 9) +
					uint32(t[j]&((1<<10)-1))*uint32(Q)) >> 10)
			}

			idx += 5
		}
	case 11:
		var t [8]uint16
		idx := 0
		for i := 0; i < N/8; i++ {
			t[0] = uint16(m[idx]) | (uint16(m[idx+1]) << 8)
			t[1] = (uint16(m[idx+1]) >> 3) | (uint16(m[idx+2]) << 5)
			t[2] = (uint16(m[idx+2]) >> 6) | (uint16(m[idx+3]) << 2) | (uint16(m[idx+4]) << 10)
			t[3] = (uint16(m[idx+4]) >> 1) | (uint16(m[idx+5]) << 7)
			t[4] = (uint16(m[idx+5]) >> 4) | (uint16(m[idx+6]) << 4)
			t[5] = (uint16(m[idx+6]) >> 7) | (uint16(m[idx+7]) << 1) | (uint16(m[idx+8]) << 9)
			t[6] = (uint16(m[idx+8]) >> 2) | (uint16(m[idx+9]) << 6)
			t[7] = (uint16(m[idx+9]) >> 5) | (uint16(m[idx+10]) << 3)

			for j := 0; j < 8; j++ {
				p[8*i+j] = int16(((1 << 10) +
					uint32(t[j]&((1<<11)-1))*uint32(Q)) >> 11)
			}

			idx += 11
		}
	default:
		panic("unsupported d")
	}
}

// Writes Compress_q(p, d) to m.
//
// Assumes p is normalized and d is in {4, 5, 10, 11}.
func (p *Poly) CompressTo(m []byte, d int) {
	// Compress_q(x, d) = ⌈(2ᵈ/q)x⌋ mod⁺ 2ᵈ
	//                  = ⌊(2ᵈ/q)x+½⌋ mod⁺ 2ᵈ
	//					= ⌊((x << d) + q/2) / q⌋ mod⁺ 2ᵈ
	//					= DIV((x << d) + q/2, q) & ((1<<d) - 1)
	//
	// We approximate DIV(x, q) by computing (x*a)>>e, where a/(2^e) ≈ 1/q.
	// For d in {10,11} we use 20,642,679/2^33, which computes division by x/q
	// correctly for 0 ≤ x < 41,522,616, which fits (q << 11) + q/2 comfortably.
	// For d in {4,5} we use 315/2^20, which doesn't compute division by x/q
	// correctly for all inputs, but it's close enough that the end result
	// of the compression is correct. The advantage is that we do not need
	// to use a 64-bit intermediate value.
	switch d {
	case 4:
		var t [8]uint16
		idx := 0
		for i := 0; i < N/8; i++ {
			for j := 0; j < 8; j++ {
				t[j] = uint16((((uint32(p[8*i+j])<<4)+uint32(Q)/2)*315)>>20) & ((1 << 4) - 1)
			}
			m[idx] = byte(t[0]) | byte(t[1]<<4)
			m[idx+1] = byte(t[2]) | byte(t[3]<<4)
			m[idx+2] = byte(t[4]) | byte(t[5]<<4)
			m[idx+3] = byte(t[6]) | byte(t[7]<<4)
			idx += 4
		}

	case 5:
		var t [8]uint16
		idx := 0
		for i := 0; i < N/8; i++ {
			for j := 0; j < 8; j++ {
				t[j] = uint16((((uint32(p[8*i+j])<<5)+uint32(Q)/2)*315)>>
					20) & ((1 << 5) - 1)
			}
			m[idx] = byte(t[0]) | byte(t[1]<<5)
			m[idx+1] = byte(t[1]>>3) | byte(t[2]<<2) | byte(t[3]<<7)
			m[idx+2] = byte(t[3]>>1) | byte(t[4]<<4)
			m[idx+3] = byte(t[4]>>4) | byte(t[5]<<1) | byte(t[6]<<6)
			m[idx+4] = byte(t[6]>>2) | byte(t[7]<<3)
			idx += 5
		}

	case 10:
		var t [4]uint16
		idx := 0
		for i := 0; i < N/4; i++ {
			for j := 0; j < 4; j++ {
				t[j] = uint16((uint64((uint32(p[4*i+j])<<10)+uint32(Q)/2)*
					2580335)>>33) & ((1 << 10) - 1)
			}
			m[idx] = byte(t[0])
			m[idx+1] = byte(t[0]>>8) | byte(t[1]<<2)
			m[idx+2] = byte(t[1]>>6) | byte(t[2]<<4)
			m[idx+3] = byte(t[2]>>4) | byte(t[3]<<6)
			m[idx+4] = byte(t[3] >> 2)
			idx += 5
		}
	case 11:
		var t [8]uint16
		idx := 0
		for i := 0; i < N/8; i++ {
			for j := 0; j < 8; j++ {
				t[j] = uint16((uint64((uint32(p[8*i+j])<<11)+uint32(Q)/2)*
					2580335)>>33) & ((1 << 11) - 1)
			}
			m[idx] = byte(t[0])
			m[idx+1] = byte(t[0]>>8) | byte(t[1]<<3)
			m[idx+2] = byte(t[1]>>5) | byte(t[2]<<6)
			m[idx+3] = byte(t[2] >> 2)
			m[idx+4] = byte(t[2]>>10) | byte(t[3]<<1)
			m[idx+5] = byte(t[3]>>7) | byte(t[4]<<4)
			m[idx+6] = byte(t[4]>>4) | byte(t[5]<<7)
			m[idx+7] = byte(t[5] >> 1)
			m[idx+8] = byte(t[5]>>9) | byte(t[6]<<2)
			m[idx+9] = byte(t[6]>>6) | byte(t[7]<<5)
			m[idx+10] = byte(t[7] >> 3)
			idx += 11
		}
	default:
		panic("unsupported d")
	}
}
