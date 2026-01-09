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
		const mask = (1 << bitWidth) - 1 // mask = 0x0f

		// For bitWidth = 4, each coefficient is stored in 4-bits.
		// 8 coefficients x 4 bits = 32 bits = 4 bytes.
		//
		// Each loop iteration prepares 4-bytes block at a time.
		for i := 0; i < N/8; i++ {
			// Load 4 bytes from the ciphertext and assemble them into a 32-bit little-endian word.
			//
			// This word represents a contiguous bitstream of 8 packed 4-bit coefficients:
			//
			// w = [ t7 | t6 | t5 | t4 | t3 | t2 | t1 | t0 ]
			//		4b	 4b	  4b   4b	4b	 4b	  4b   4b
			//
			// where t0 occupies the least significant 4 bits.
			w := uint32(ct[idx]) |
				uint32(ct[idx+1])<<8 |
				uint32(ct[idx+2])<<16 |
				uint32(ct[idx+3])<<24

			// Extract and decompress the 8 coefficients from the 32-bit word.
			for j := 0; j < 8; j++ {

				// Step 1: Extract the j-th 4-bit value.
				//
				// - Shift right by (4 * bitWidth) to align the desired coefficient to the least
				// significant bits.
				// - Mask with 0x0f to keep exactly 4-bits.
				//
				// This recovers the compressed value:
				//
				// t ∈ {0, 1, ..... 15}
				//
				// which represents the index of a quantization bucket.
				t := (w >> (j * bitWidth)) & mask

				// Step-2: Decompress (dequantize) the 4-bit value back into Z_Q.
				//
				// This computes:
				//
				//   round(t * Q / 16)
				//
				// - Multiply by Q to scale back into the modulus range.
				// - Add mask (= 2^bitWidth - 1) to implement rounding instead of truncation
				// toward zero.
				// - Shift right by bitWidth (divide by 16)
				//
				// The result is a representative value for the entire quantization interval
				// corresponding to t.
				p.coeffs[8*i+j] = int16((uint32(t)*Q + mask) >> bitWidth)
			}

			// Advance the ciphertext index by 4-bytes (32 bits)
			idx += 4
		}
	case 5:
		const bitWidth = 5
		const mask = (1 << bitWidth) - 1 // mask = 0x1f

		// For bitWidth = 5, each coefficient is stored in 5-bits.
		// 8 coefficients x 5 bits = 40 bits = 5 bytes.
		//
		// Each loop iteration prepares 5-bytes block at a time.
		for i := 0; i < N/8; i++ {
			// Load 4 bytes from the ciphertext and assemble them into a 40-bit little-endian word.
			//
			// This word represents a contiguous bitstream of 8 packed 5-bit coefficients:
			//
			// w = [t7 | t6 | t5 | t4 | t3 | t2 | t1 | t0 ]
			//		5b	 5b	  5b   5b	5b	 5b	  5b   5b
			//
			// where t0 occupies the least significant 5 bits.
			w := uint64(ct[idx]) |
				uint64(ct[idx+1])<<8 |
				uint64(ct[idx+2])<<16 |
				uint64(ct[idx+3])<<24 |
				uint64(ct[idx+4])<<32

			// Extract and decompress the 8 coefficients from the 40-bit word.
			for j := 0; j < 8; j++ {

				// Step 1: Extract the j-th 5-bit value.
				//
				// - Shift right by (5 * bitWidth) to align the desired coefficient to the least
				// significant bits.
				// - Mask with 0x0f to keep exactly 5-bits.
				//
				// This recovers the compressed value:
				//
				// t ∈ {0, 1, ..... 31}
				//
				// which represents the index of a quantization bucket.
				t := (w >> (j * bitWidth)) & mask

				// Step-2: Decompress (dequantize) the 5-bit value back into Z_Q.
				//
				// This computes:
				//
				//   round(t * Q / 32)
				//
				// - Multiply by Q to scale back into the modulus range.
				// - Add mask (= 2^bitWidth - 1) to implement rounding instead of truncation
				// toward zero.
				// - Shift right by bitWidth (divide by 32)
				//
				// The result is a representative value for the entire quantization interval
				// corresponding to t.
				p.coeffs[8*i+j] = int16((uint32(t)*Q + mask) >> bitWidth)
			}

			// Advance the ciphertext index by 5-bytes (40 bits)
			idx += 5
		}

	case 10:
		const bitWidth = 10
		const mask = (1 << bitWidth) - 1

		for i := 0; i < N/4; i++ {
			w := uint64(ct[idx]) |
				uint64(ct[idx+1])<<8 |
				uint64(ct[idx+2])<<16 |
				uint64(ct[idx+3])<<24 |
				uint64(ct[idx+4])<<32

			// Extract and decompress the 8 coefficients from the 40-bit word.
			for j := 0; j < 4; j++ {
				// Step 1: Extract the j-th 5-bit value.
				//
				// - Shift right by (5 * bitWidth) to align the desired coefficient to the least
				// significant bits.
				// - Mask with 0x0f to keep exactly 5-bits.
				//
				// This recovers the compressed value:
				//
				// t ∈ {0, 1, ..... 31}
				//
				// which represents the index of a quantization bucket.
				t := (w >> (j * bitWidth)) & mask

				// Step-2: Decompress (dequantize) the 5-bit value back into Z_Q.
				//
				// This computes:
				//
				//   round(t * Q / 32)
				//
				// - Multiply by Q to scale back into the modulus range.
				// - Add mask (= 2^bitWidth - 1) to implement rounding instead of truncation
				// toward zero.
				// - Shift right by bitWidth (divide by 32)
				//
				// The result is a representative value for the entire quantization interval
				// corresponding to t.
				p.coeffs[4*i+j] = int16((uint32(t)*Q + mask) >> bitWidth)
			}

			// Advance the ciphertext index by 5-bytes (40 bits)
			idx += 5
		}
	case 11:
		const bitWidth = 11
		const mask = (1 << bitWidth) - 1 // 0x7ff

		// Process all N coefficients
		for i := 0; i < N; i++ {
			// Move the bitPos by 3-bits because 11 mod 8 = 3, the starting bit offset advances by 3 bits each time.
			bytePos := idx >> 3
			shift := idx & 7

			// Load a 24-bit window (3 bytes) to guarantee we can extract 11 contiguous bits regardless of alignment.
			w := uint32(ct[bytePos]) |
				uint32(ct[bytePos+1])<<8 |
				uint32(ct[bytePos+2])<<16

			// Step 1: Align the desired 11-bit field to the LSBs
			// Step 2: Mask to keep exactly 11 bits
			t := (w >> shift) & mask

			// Step 3: Decompress (dequantize) back into Z_Q
			//
			// Computes:
			//   round(t * Q / 2^11)
			//
			// - Multiply by Q to scale back to modulus range
			// - Add mask (= 2^11 − 1) to round instead of truncate towards zero.
			// - Shift right by bitWidth (divide by 2048)
			p.coeffs[i] = int16((uint32(t)*Q + mask) >> bitWidth)

			// Advance by one 11-bit coefficient
			idx += bitWidth
		}
	}
}

// CompressMessage extracts a 256-bit message from a polynomial by thresholding each coefficient into
// a single bit.
func (p *Poly) CompressMessage(m []byte) {
	// q is the modulus Q represented as int16 for coefficient comparison.
	q := int16(Q)

	// Define decision thresholds that split Z_Q into regions.
	//
	// low = Q / 4
	// high = 3Q / 4
	//
	// These boundaries are chosen so that values near 0 or Q decode to bit 0, and values near
	// Q/2 decode to bit 1 with tolerance for noise. And (+2) added to round-to-nearest when dividing.
	low := (q + 2) / 4
	high := (3*q + 2) / 4

	// Process 256-coefficients in block of 8.
	// Each block produces one output byte (8 message bits).
	for i := 0; i < N/8; i++ {
		var b byte // byte accumulator for each message byte.
		for j := 0; j < 8; j++ {
			// Read the polynomial coefficient corresponding to the j-th bit of the current message byte.
			t := p.coeffs[8*i+j]
			// Decision rule:
			//
			// If the coefficient lies in the middle half of Z_Q, between Q/4 and 3Q/4, we decode it
			// as bit = 1.
			//
			// Otherwise (near 0 or near Q), decode as bit = 0.
			if t > low && t < high {
				//0 -------- Q/4 ---- Q/2 ---- 3Q/4 -------- Q
				//|    0     |   1    |   1    |     0       |
				b |= 1 << j
			}
			m[i] = b
		}
	}
}

// DecompressMessage embeds a 256-bit message into a polynomial by mapping each bit to either 0 or +-(Q+1)/2
// in centered modular representation.
func (p *Poly) DecompressMessage(m []byte) {
	// Process the message in blocks of 8 bits (one byte).
	// Each bit is expanded into one polynomial coefficients.
	for i := 0; i < N/8; i++ {
		for j := 0; j < 8; j++ {
			// Extract the j-th bit from the i-th message byte.
			// bit ∈ {0, 1}
			bit := (m[i] >> j) & 1

			// Map the message bit into Z_Q using centered representation.
			//
			// If bit == 0:
			//	-int16(0) = 0
			// 0 & ((Q+1)/2) = 0
			//
			// If bit == 1:
			//  -int16(1) == -1 (all bit set)
			//	 --> [16] 1s (1111 1111 1111 1111) and if MSB is 1 then sign bit is negative.
			//
			// Encode the message bit as a polynomial coefficient.
			//	bit = 0 --> coefficient = 0
			//	bit = 1 --> coefficient = (Q+1)/2 (the modular representative of Q/2).
			//
			// The coefficient is stored using centered modular representation, so this value
			// may later be represented as a negative int16 after subsequent arithmetic, even
			// though it is assigned positively on the threshold range.
			p.coeffs[8*i+j] = -int16(bit) & ((int16(Q) + 1) / 2)
		}
	}
}
