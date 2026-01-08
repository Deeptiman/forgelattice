package poly

// CompressedPolySize returns the number of the bytes required to encode a polynomial compressed to
// d bits (bitWidth) per coefficient.
//
// The size depends on the packing density:
//
//	d=4  -> 256 coefficients x 4 bits  = 128 bytes
//	d=5  -> 256 coefficients x 5 bits  = 160 bytes
//	d=10 -> 256 coefficients x 10 bits = 320 bytes
//	d=11 -> 256 coefficients x 11 bits = 352 bytes
func CompressedPolySize(d int) int {
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
		panic("unsupported input to support fixed-point arithmetic")
	}
}

func (p *Poly) Compress(bitWidth int, ct []byte) {
	idx := 0
	// Fixed-point approximation of:
	// floor((x * 2^d + Q/2) / Q)
	switch bitWidth {
	case 4:
		// Process 8-coefficients at a time. For bitWidth=4, each coefficient is compressed of 4-bits.
		//
		for i := 0; i < N/8; i++ {
			var t [8]uint16
			for j := 0; j < 8; j++ {
				// t = round(p.coeffs[k] * 16 / Q) mod 16
				//
				// Step-1: Multiply by 16 (2^4) to scale into 4-bit space.
				// This corresponds to the numerator of (x * 16) / Q.
				//
				// x_scaled = p.coeffs[k] << 4
				//
				// Cast uint32 to avoid overflow during the shift.
				x0 := uint32(p.coeffs[8*i+j]) << 4
				//
				// Step-2: Add Q/2 to implement rounding to nearest instead of truncation towards zero.
				// This ensures unbiased quantization and is required for correctness in Kyber's decryption
				// error bounds.
				//
				// x_bound = (x * 32) + Q/2
				roundingQ := uint32(Q) / 2
				//
				// Step-3: Why 20159 & right shift of 26-bits?
				//
				// round(2^26/Q)
				//
				// 20159 = scaled reciprocal of Q
				// 2^26 = 67,108,864
				// 67,108,864/3329 = 20158.8
				//
				// This replaces the division by Q with fix-point arithmetic:
				// 20159 is a precomputed reciprocal of Q scaled by 2^26. Multiplication by this constant
				// followed by a right shift of 26 bits implements a constant-time approximation of division
				// by Q with correct rounding.
				//
				//
				// Step-4: Mask 4-bits to ensure result lies in [0...15].
				t[j] = uint16((uint64((x0)+roundingQ)*20159)>>26) & ((1 << 4) - 1)
			}
			// Pack the 8-compressed 4-bits coefficients into 4-bytes.
			// Each byte stores two coefficients:
			//	- lower nibble = t[even]
			// 	- upper nibble = t[odd]
			ct[idx] = byte(t[0]) | byte(t[1]<<4)
			ct[idx+1] = byte(t[2]) | byte(t[3]<<4)
			ct[idx+2] = byte(t[4]) | byte(t[5]<<4)
			ct[idx+3] = byte(t[6]) | byte(t[7]<<4)

			// Advance output index by 4-bytes (32-bits)
			idx += 4
		}
	case 5:
		var t [8]uint16
		// Process 8-coefficients at a time. For bitWidth=5, each coefficient is compressed of 5-bits.
		// 8 x 5 bits = 40 bits = 5 bytes of output.
		for i := 0; i < N/8; i++ {
			for j := 0; j < 8; j++ {
				// t = round(p.coeffs[k] * 32 / Q) mod 32
				//
				// Step-1: Multiply by 32 (2^5) to scale into 4-bit space.
				// This corresponds to the numerator of (x * 32) / Q.
				//
				// x_scaled = p.coeffs[k] << 5
				//
				// Cast uint32 to avoid overflow during the shift.
				x0 := uint32(p.coeffs[8*i+j]) << 5
				//
				// Step-2: Add Q/2 to implement rounding to nearest instead of truncation towards zero.
				// This ensures unbiased quantization and is required for correctness in Kyber's decryption
				// error bounds.
				//
				// x_bound = (x * 32) + Q/2
				roundingQ := uint32(Q) / 2
				//
				// Step-3: Why 20159 & right shift of 26-bits?
				//
				// round(2^26/Q)
				//
				// 20159 = scaled reciprocal of Q
				// 2^26 = 67,108,864
				// 67,108,864/3329 = 20158.8
				//
				// This replaces the division by Q with fix-point arithmetic:
				// 20159 is a precomputed reciprocal of Q scaled by 2^26. Multiplication by this constant
				// followed by a right shift of 26 bits implements a constant-time approximation of division
				// by Q with correct rounding.
				//
				//
				// Step-4: Mask 5-bits to ensure result lies in [0...31].
				t[j] = uint16((((x0)+roundingQ)*20159)>>26) & ((1 << 5) - 1)
			}

			// Pack the 8 compressed coefficients into 5 bytes.
			// Since 5 does not divide 8, coefficients span byte boundaries.
			// The layout below packs the coefficients contiguously without padding.
			ct[idx+0] = byte(t[0]) | byte(t[1]<<5)
			ct[idx+1] = byte(t[1]>>3) | byte(t[2]<<2) | byte(t[3]<<7)
			ct[idx+2] = byte(t[3]>>1) | byte(t[4]<<4)
			ct[idx+3] = byte(t[4]>>4) | byte(t[5]<<1) | byte(t[6]<<6)
			ct[idx+4] = byte(t[6]>>2) | byte(t[7]<<3)

			// Advance output index by 5 bytes (40 bits).
			idx += 5
		}
	case 10:
		// Process 4 polynomial coefficients at a time.
		// For bitWidth=10, each coefficient is compared to 10 bits.
		// 4 x 10 bits = 40 bits, which are packed contiguously into 5 bytes.
		for i := 0; i < N/4; i++ {
			// Temporary buffer holding the 4 compressed 10-bit values.
			// Each t[j] ∈ [0...1023] represents a quantized coefficient.
			var t [4]uint16
			for j := 0; j < 4; j++ {
				// t = round(p.coeffs[k] * 1024 / Q) mod 1024
				//
				// Step-1: Multiply by 1024 (2^10) to scale into 10-bit space.
				// This corresponds to the numerator of (x * 1024) / Q.
				//
				// x_scaled = p.coeffs[k] << 10
				//
				// Cast uint32 to avoid overflow during the shift.
				x0 := uint32(p.coeffs[4*i+j]) << 10
				//
				// Step-2: Add Q/2 to implement rounding to nearest instead of truncation towards zero.
				// This ensures unbiased quantization and is required for correctness in Kyber's decryption
				// error bounds.
				//
				// x_bound = (x * 32) + Q/2
				roundingQ := uint32(Q) / 2
				//
				// Step-3: Why 2580335 & right shift of 33-bits?
				//
				// round(2^33/Q)
				//
				// 2580335 = scaled reciprocal of Q
				// 2^33 = 8,589,934,592
				// 8,589,934,592/3329 = 2580334.81
				//
				// This replaces the division by Q with fix-point arithmetic:
				// 2580335 is a precomputed reciprocal of Q scaled by 2^33. Multiplication by this constant
				// followed by a right shift of 33 bits implements a constant-time approximation of division
				// by Q with correct rounding.
				t[j] = uint16((uint64((x0)+roundingQ)*2580335)>>33) & ((1 << 10) - 1)
			}

			// Pack 4 compressed 10-bit coefficients into 5-bytes.
			// Since 10 does not divide 8, coefficients span byte boundaries.
			// The layout below packs the coefficients contiguously without padding.
			//
			// Each coefficient contributes 8-bits to the current byte, and its remaining
			// 2 bits are carried forward and combined with the next coefficient.

			// Byte 0:
			// - bits 0...7: lower 8 bits of t[0]
			ct[idx+0] = byte(t[0])

			// Byte 1:
			// - bits 0...1: upper 2 bits of t[0]
			// - bits 2...7: lower 6 bits of t[1]
			ct[idx+1] = byte(t[0]>>8) | byte(t[1]<<2)

			// Byte 2:
			// - bits 0...3: upper 4 bits of t[1]
			// - bits 4...7: lower 4 bits of t[2]
			ct[idx+2] = byte(t[1]>>6) | byte(t[2]<<4)

			// Byte 3:
			// - bits 0...5: upper 6 bits of t[2]
			// - bits 6...7: lower 2 bits of t[3]
			ct[idx+3] = byte(t[2]>>4) | byte(t[3]<<6)

			// Byte 4:
			// - bits 0...7: upper 8 bits of t[3]
			ct[idx+4] = byte(t[3] >> 2)

			// Advance output index by 5 bytes (40 bits).
			idx += 5
		}
	case 11:
		var t [8]uint16
		// Process 8 polynomial coefficients at a time.
		// For bitWidth=11, each coefficient is compared to 11 bits.
		// 8 x 11 bits = 88 bits, which are packed contiguously into 11 bytes.
		for i := 0; i < N/8; i++ {
			// Temporary buffer holding the 8 compressed 11-bit values.
			// Each t[j] ∈ [0...2047] represents a quantized coefficient.
			for j := 0; j < 8; j++ {
				// t = round(p.coeffs[k] * 2048 / Q) mod 2048
				//
				// Step-1: Multiply by 2048 (2^11) to scale into 11-bit space.
				// This corresponds to the numerator of (x * 2048) / Q.
				//
				// x_scaled = p.coeffs[k] << 11
				//
				// Cast uint32 to avoid overflow during the shift.
				x0 := uint32(p.coeffs[8*i+j]) << 11
				//
				// Step-2: Add Q/2 to implement rounding to nearest instead of truncation towards zero.
				// This ensures unbiased quantization and is required for correctness in Kyber's decryption
				// error bounds.
				//
				// x_bound = (x * 32) + Q/2
				roundingQ := uint32(Q) / 2
				//
				// Step-3: Why 2580335 & right shift of 33-bits?
				//
				// round(2^33/Q)
				//
				// 2580335 = scaled reciprocal of Q
				// 2^33 = 8,589,934,592
				// 8,589,934,592/3329 = 2580334.81
				//
				// This replaces the division by Q with fix-point arithmetic:
				// 2580335 is a precomputed reciprocal of Q scaled by 2^33. Multiplication by this constant
				// followed by a right shift of 33 bits implements a constant-time approximation of division
				// by Q with correct rounding.
				t[j] = uint16((uint64((x0)+roundingQ)*2580335)>>33) & ((1 << 11) - 1)
			}

			// Byte 0:
			// - bits 0...7: lower 8 bits of t[0]
			ct[idx+0] = byte(t[0])

			// Byte 1:
			// - bits 0...3: upper 3 bits of t[0]
			// - bits 3...7: lower 5 bits of t[1]
			ct[idx+1] = byte(t[0]>>8) | byte(t[1]<<3)

			// Byte 2:
			// - bits 0...5: upper 6 bits of t[1]
			// - bits 6...7: lower 2 bits of t[2]
			ct[idx+2] = byte(t[1]>>5) | byte(t[2]<<6)

			// Byte 3:
			// - bits 0...7: middle 8 bits of t[2] (bits 2..9)
			ct[idx+3] = byte(t[2] >> 2)

			// Byte 4:
			// - bit 0: highest bits of t[2]
			// - bits 1...7: lower 7 bits of t[3]
			ct[idx+4] = byte(t[2]>>10) | byte(t[3]<<1)

			// Byte 5:
			// - bits 0...3: upper 4 bits of t[3]
			// - bits 4...7: lower 4 bits of t[4]
			ct[idx+5] = byte(t[3]>>7) | byte(t[4]<<4)

			// Byte 6:
			// - bits 0...6: upper 7 bits of t[4]
			// - bit 7: 	 lower 1 bit of t[5]
			ct[idx+6] = byte(t[4]>>4) | byte(t[5]<<7)

			// Byte 7:
			// - bits 0...7: middle 8 bits of t[5] (bits 1..8)
			ct[idx+7] = byte(t[5] >> 1)

			// Byte 8:
			// - bits 0...1: upper 2 bits of t[5]
			// - bits 2...7: lower 6 bits of t[6]
			ct[idx+8] = byte(t[5]>>9) | byte(t[6]<<2)

			// Byte 9:
			// - bits 0...4: upper 5 bits of t[6]
			// - bits 5...7: lower 3 bits of t[7]
			ct[idx+9] = byte(t[6]>>6) | byte(t[7]<<5)

			// Byte 10:
			// - bits 0...7: upper 8 bits of t[7]
			ct[idx+10] = byte(t[7] >> 3)

			// Advance output index by 11 bytes (88 bits).
			idx += 11
		}
	}
}

func (p *Poly) Decompress(bitWidth int, ct []byte) {
	idx := 0
	switch bitWidth {
	case 4:
		const bitWidth = 4
		const mask = (1 << bitWidth) - 1

		for i := 0; i < N/8; i++ {
			// Load 4-bytes = 32-bits
			w := uint32(ct[idx]) |
				uint32(ct[idx+1])<<8 |
				uint32(ct[idx+2])<<16 |
				uint32(ct[idx+3])<<24

			// Extract 8 coefficients
			for j := 0; j < 8; j++ {
				t := (w >> (bitWidth * j)) & mask
				p.coeffs[8*i+j] = int16((uint32(t)*Q + mask) >> bitWidth)
			}
			idx += 4
		}

	case 5:
		const bitWidth = 5
		const mask = (1 << bitWidth) - 1

		for i := 0; i < N/8; i++ {
			// Load 5-bytes = 40-bits
			w := uint64(ct[idx]) |
				uint64(ct[idx+1])<<8 |
				uint64(ct[idx+2])<<16 |
				uint64(ct[idx+3])<<24 |
				uint64(ct[idx+4])<<32

			// Extract 8 coefficients
			for j := 0; j < 8; j++ {
				t := (w >> (bitWidth * j)) & mask
				p.coeffs[8*i+j] = int16((uint32(t)*Q + mask) >> bitWidth)
			}
			idx += 5
		}

	case 10:
		for i := 0; i < N/4; i++ {
			t0 := uint16(ct[idx+0]) | (uint16(ct[idx+1]) << 8)
			t1 := (uint16(ct[idx+1]) >> 2) | (uint16(ct[idx+2]) << 6)
			t2 := (uint16(ct[idx+2]) >> 4) | (uint16(ct[idx+3]) << 4)
			t3 := (uint16(ct[idx+3]) >> 6) | (uint16(ct[idx+4]) << 2)

			p.coeffs[4*i+0] = int16((uint32(t0&0x3ff)*Q + ((1 << bitWidth) - 1)) >> bitWidth)
			p.coeffs[4*i+1] = int16((uint32(t1&0x3ff)*Q + ((1 << bitWidth) - 1)) >> bitWidth)
			p.coeffs[4*i+2] = int16((uint32(t2&0x3ff)*Q + ((1 << bitWidth) - 1)) >> bitWidth)
			p.coeffs[4*i+3] = int16((uint32(t3&0x3ff)*Q + ((1 << bitWidth) - 1)) >> bitWidth)

			idx += 5
		}
	case 11:
		const bitWidth = 11
		const mask = (1 << bitWidth) - 1

		bitpos := 0
		for i := 0; i < N; i++ {
			shift := bitpos & 7
			bytePos := bitpos >> 3
			t := uint32(ct[bytePos]) >> shift
			t |= uint32(ct[bytePos+1]) << (8 - shift)
			t |= uint32(ct[bytePos+2]) << (16 - shift)

			t &= mask // mask = (1<<11)-1

			p.coeffs[i] = int16((t*Q + mask) >> bitWidth)

			bitpos += bitWidth
		}
	}
}

func (p *Poly) CompressMessage(m []byte) {
	q := int16(Q)
	low := (q + 2) / 4
	high := (3*q + 2) / 4
	for i := 0; i < 32; i++ {
		var b byte
		for j := 0; j < 8; j++ {
			t := p.coeffs[8*i+j]
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
			p.coeffs[8*i+j] = -int16(bit) & ((int16(Q) + 1) / 2)
		}
	}
}
