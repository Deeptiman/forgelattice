package keccak

import "math/bits"

var roundConstants = [24]uint64{
	0x0000000000000001, 0x0000000000008082,
	0x800000000000808A, 0x8000000080008000,
	0x000000000000808B, 0x0000000080000001,
	0x8000000080008081, 0x8000000000008009,
	0x000000000000008A, 0x0000000000000088,
	0x0000000080008009, 0x000000008000000A,
	0x000000008000808B, 0x800000000000008B,
	0x8000000000008089, 0x8000000000008003,
	0x8000000000008002, 0x8000000000000080,
	0x000000000000800A, 0x800000008000000A,
	0x8000000080008081, 0x8000000000008080,
	0x0000000080000001, 0x8000000080008008,
}

func idx(x, y int) int { return x + 5*y }

func RhoOffsets() [25]int {
	var rho [25]int
	x, y := 1, 0
	for t := 0; t < 24; t++ {
		rho[5*y+x] = ((t + 1) * (t + 2) / 2) % 64
		x, y = y, (2*x+3*y)%5
	}
	return rho
}

func Theta(a *[25]uint64) {
	var col, diagonal [5]uint64

	for x := 0; x < 5; x++ {
		col[x] = a[idx(x, 0)] ^ a[idx(x, 1)] ^ a[idx(x, 2)] ^ a[idx(x, 3)] ^ a[idx(x, 4)]
	}

	for x := 0; x < 5; x++ {
		diagonal[x] = col[(x+4)%5] ^ bits.RotateLeft64(col[(x+1)%5], 1)
	}

	for x := 0; x < 5; x++ {
		for y := 0; y < 5; y++ {
			a[idx(x, y)] ^= diagonal[x]
		}
	}
}

func Rho(a *[25]uint64, rhoOffsets [25]int) {
	for i := 0; i < 25; i++ {
		a[i] = bits.RotateLeft64(a[i], rhoOffsets[i])
	}
}

func Pi(a *[25]uint64) {
	var b [25]uint64
	for x := 0; x < 5; x++ {
		for y := 0; y < 5; y++ {
			b[idx(y, (2*x+3*y)%5)] = a[idx(x, y)]
		}
	}
	*a = b
}

func Chi(a *[25]uint64) {
	for y := 0; y < 5; y++ {
		var row [5]uint64
		for x := 0; x < 5; x++ {
			row[x] = a[idx(x, y)]
		}
		for x := 0; x < 5; x++ {
			a[idx(x, y)] = row[x] ^ (^row[(x+1)%5] & row[(x+2)%5])
		}
	}
}

func Strike(a *[25]uint64, round int) {
	a[0] ^= roundConstants[round]
}

func Round24(a *[25]uint64, round int) {
	Theta(a)
	Rho(a, RhoOffsets())
	Pi(a)
	Chi(a)
	Strike(a, round)
}

func PermuteWith1600(a *[25]uint64) {
	for round := 0; round < 24; round++ {
		Round24(a, round)
	}
}
