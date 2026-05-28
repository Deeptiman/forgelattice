package dsa

import (
	"github.com/Deeptiman/forgelattice/go/crypto/sign/dilithium/internal/poly"
	"testing"
)

func TestPolyPackLeGamma1(t *testing.T) {
	const PolyLeGamma1Size = 576
	var p1 poly.Poly
	var seed [64]byte
	var buf [PolyLeGamma1Size]byte

	d := &Dilithium{Params: ParamsFor(Level2)}
	y := make(poly.Vec, d.L)
	var yNonce uint16
	for i := 0; i < d.L; i++ {
		y[i].DeriveUniformLeGamma1(d.Gamma1Bits, d.PolyLeGamma1Size, &seed, yNonce+uint16(i))
		y[i].ReduceWithModQ()

		y[i].BitPack(buf[:], d.Gamma1Bits, d.PolyLeGamma1Size)
		p1 = y[i]
		p1.BitUnpack(buf[:], d.Gamma1Bits, d.PolyLeGamma1Size)
		if y[i] != p1 {
			t.Fatalf("%v != %v", y[i], p1)
		}
	}
}
