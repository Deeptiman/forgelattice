package keccak

import "math/bits"

// Lanes represents the 1600-bit Keccak state as 25 lanes of 64 bits each.
//
// The state is conceptually a 5x5 matrix of lanes:
//
//	l[x, y] with 0 <= x,y < 5
//
// It is stored in linear form using the mapping:
//
//	l[x, y] --> lanes[x + 5*y]
//
// This layout matches the Keccak-f[1600] specification and is used by all permutation
// steps (θ, ρ, π, χ, ι).
type Lanes [25]uint64

// idx maps 2D Keccak coordinates (x, y) into a linear index.
//
// The state is stored in row order:
//
// l[x, y] ---> l[x + 5y]
func idx(x, y int) int { return x + 5*y }

// RhoOffsets computes the rotation left by a fixed amount that depends on its position.
// The offsets are defined by the Keccak specification and ensure that bits are spread
// across different bit positions in subsequent rounds.
func RhoOffsets() [25]int {
	var rho [25]int
	x, y := 1, 0
	for t := 0; t < 24; t++ {
		rho[x+5*y] = ((t + 1) * (t + 2) / 2) % 64
		x, y = y, (2*x+3*y)%5
	}
	return rho
}

// Theta implements the θ step of Keccak.
//
// Theta mixes the bit with the parity of its column and adjacent columns.
// This step provides diffusion across the entire state.
func (l *Lanes) Theta() {
	var col, diagonal [5]uint64

	for x := 0; x < 5; x++ {
		col[x] = l[idx(x, 0)] ^ l[idx(x, 1)] ^ l[idx(x, 2)] ^ l[idx(x, 3)] ^ l[idx(x, 4)]
	}

	// Compute the diagonal correction for each column.
	for x := 0; x < 5; x++ {
		diagonal[x] = col[(x+4)%5] ^ bits.RotateLeft64(col[(x+1)%5], 1)
	}

	// Apply the correction to every lane in the column.
	for x := 0; x < 5; x++ {
		for y := 0; y < 5; y++ {
			l[idx(x, y)] ^= diagonal[x]
		}
	}
}

// Rho implements the ρ steps of Keccak.
//
// Each lane is rotated left by a position-specific offset.
// This step moves bits within each lane to different bit positions.
func (l *Lanes) Rho(rhoOffsets [25]int) {
	for i := 0; i < 25; i++ {
		l[i] = bits.RotateLeft64(l[i], rhoOffsets[i])
	}
}

// Pi implements the π step of Keccak.
//
// Pi permutes the positions of the lanes within the state, rearranging them to break column-wise
// structure.
func (l *Lanes) Pi() {
	var a [25]uint64
	for x := 0; x < 5; x++ {
		for y := 0; y < 5; y++ {
			a[idx(y, (2*x+3*y)%5)] = l[idx(x, y)]
		}
	}
	*l = a
}

// Chi implements the χ step of Keccak.
//
// Chi is the only non-linear step. It operates on each row independently combining bits using
// AND, NOT, and XOR operations.
func (l *Lanes) Chi() {
	for y := 0; y < 5; y++ {
		var row [5]uint64
		for x := 0; x < 5; x++ {
			row[x] = l[idx(x, y)]
		}
		for x := 0; x < 5; x++ {
			// Triple bluff:
			//
			// 1. Negation (^row[(x+1)%5]) inverts the bits of the neighbouring
			// lane breaking linear expectations.
			//
			// 2. AND creates (^row[(x+1)%5] & row[(x+2)%5]) conditional dependency
			// on two neighbours. A bit is returned only if both conditions are met.
			//
			// 3. XOR with the original lane (⊕ row[x]) injects this conditional mask
			// to back into the state but output cannot be recomputed as a linear function
			// of the inputs.
			l[idx(x, y)] = row[x] ^ (^row[(x+1)%5] & row[(x+2)%5])
		}
	}
}

// Strike applies the Iota(ι) step of Keccak.
//
// The round constant is XORed into lane (0, 0) to break symmetry between rounds.
func (l *Lanes) Strike(round int) {
	l[0] ^= RC[round]
}

// Round applies the one round of the Keccak-f[1600] permutation.
//
// Each round consist of:
// θ → ρ → π → χ → ι
func (l *Lanes) Round(round int) {
	l.Theta()
	l.Rho(RhoOffsets())
	l.Pi()
	l.Chi()
	l.Strike(round)
}

// PermuteWith1600 applies the full Keccak-f[1600] permutation.
//
// It executes 24 rounds over the 1600-bit state.
// This permutation is used by SHA-3 and SHAKE.
func (l *Lanes) PermuteWith1600() {
	for r := 0; r < 24; r++ {
		l.Round(r)
	}
}
