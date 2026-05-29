package poly

import (
	"github.com/Deeptiman/forgelattice/crypto/dsa/internal/common"
)

func (v Vec) Add(p Vec) Vec {
	dimensions := len(v)
	q := make(Vec, dimensions)
	for i := 0; i < dimensions; i++ {
		q[i].Add(&v[i], &p[i])
	}
	return q
}

func (v Vec) Sub(p Vec) Vec {
	dimensions := len(v)
	q := make(Vec, dimensions)
	for i := 0; i < dimensions; i++ {
		q[i].Sub(&v[i], &p[i])
	}
	return q
}

func (v Vec) MultiplyBy2ToD() Vec {
	dimensions := len(v)
	q := make(Vec, dimensions)
	for i := 0; i < dimensions; i++ {
		q[i].MultiplyBy2ToD(&v[i])
	}
	return q
}

func (v Vec) ExpandS1(secretSeed *[64]byte, eta int) {
	for i := 0; i < len(v); i++ {
		v[i].RejectionBoundPoly(secretSeed, eta, uint16(i))
	}
}

func (v Vec) ExpandS2(secretSeed *[64]byte, eta, L int) {
	dimensions := len(v)
	for i := 0; i < dimensions; i++ {
		v[i].RejectionBoundPoly(secretSeed, eta, uint16(i+L))
	}
}

func (v Vec) PackPublicKeyT1(buf []byte) {
	offset := 0
	for i := 0; i < len(v); i++ {
		v[i].PackPublicKeyT1(buf[offset:])
		offset += common.PolyT1PackSize
	}
}

func (v Vec) Power2Round(t0, t1 Vec) {
	for i := 0; i < len(v); i++ {
		v[i].Power2Round(&t0[i], &t1[i])
	}
}

func (v Vec) Le2QUsingCIRCL() {
	for i := 0; i < len(v); i++ {
		v[i].Le2QUsingCIRCL()
	}
}

func (v Vec) ReduceLe2QModQ() {
	for i := 0; i < len(v); i++ {
		v[i].ReduceLe2QModQ()
	}
}

func (v Vec) Decompose(alpha int) (Vec, Vec) {
	dimensions := len(v)
	v1 := make(Vec, dimensions)
	v2 := make(Vec, dimensions)
	for i := 0; i < dimensions; i++ {
		v1[i], v2[i] = v[i].Decompose(alpha)
	}
	return v1, v2
}

func (v Vec) PackLeqEta(buf []byte, dim int, Eta uint32, DoubleEtaBits, PolyLeqEtaSize int) {
	offset := 0
	for i := 0; i < dim; i++ {
		v[i].PackLeqEta(buf[offset:], Eta, DoubleEtaBits, PolyLeqEtaSize)
		offset += PolyLeqEtaSize
	}
}

func (v Vec) UnpackLeqEta(buf []byte, dim int, Eta uint32, DoubleEtaBits, PolyLeqEtaSize int) {
	offset := 0
	for i := 0; i < dim; i++ {
		v[i].UnpackLeqEta(buf[offset:], Eta, DoubleEtaBits, PolyLeqEtaSize)
		offset += PolyLeqEtaSize
	}
}

func (v Vec) PackT0(buf []byte, K int) {
	offset := 0
	for i := 0; i < K; i++ {
		v[i].PackT0(buf[offset:])
		offset += common.PolyT0PackSize
	}
}

func (v Vec) UnpackT0(buf []byte, K int) {
	offset := 0
	for i := 0; i < K; i++ {
		v[i].UnpackT0(buf[offset:])
		offset += common.PolyT0PackSize
	}
}

func (v Vec) PackT1(buf []byte, K int) {
	offset := 0
	for i := 0; i < K; i++ {
		v[i].PackT1(buf[offset:])
		offset += common.PolyT1PackSize
	}
}

func (v Vec) UnpackT1(buf []byte, K int) {
	offset := 0
	for i := 0; i < K; i++ {
		v[i].UnpackT1(buf[offset:])
		offset += common.PolyT1PackSize
	}
}

func (v Vec) Encode(packSize, gamma1Bits int) []byte {
	offset := 0
	dimensions := len(v)
	packedBytes := make([]byte, packSize*dimensions)
	for i := 0; i < dimensions; i++ {
		v[i].Encode(packSize, gamma1Bits, packedBytes[offset:])
		offset += packSize
	}
	return packedBytes
}

func (v Vec) ExceedsBound(bound uint32) bool {
	for i := 0; i < len(v); i++ {
		if v[i].ExceedsBound(bound) {
			return true
		}
	}
	return false
}

func (v Vec) SigPack(buf []byte, gamma1Bits, polyLeGamma1Size int) {
	offset := 0
	for i := 0; i < len(v); i++ {
		v[i].BitPack(buf[offset:], gamma1Bits, polyLeGamma1Size)
		offset += polyLeGamma1Size
	}
}

func (v Vec) SigUnPack(buf []byte, gamma1Bits, polyLeGamma1Size int) {
	offset := 0
	for i := 0; i < len(v); i++ {
		v[i].BitUnpack(buf[offset:], gamma1Bits, polyLeGamma1Size)
		offset += polyLeGamma1Size
	}
}

func (v Vec) MakeHint(Gamma2 int, r1, w1 Vec) int {
	hintCount := 0
	for i := 0; i < len(v); i++ {
		hintCount += v[i].MakeHint(Gamma2, &r1[i], &w1[i])
	}
	return hintCount
}

func (v Vec) UseHint(gamma2 int, w0, w1 Vec) {
	for i := 0; i < len(v); i++ {
		v[i].UseHint(gamma2, &w0[i], &w1[i])
	}
}

func (v Vec) PackHint(buf []byte, omega int) uint8 {
	x := uint8(0)
	for i := 0; i < len(v); i++ {
		x = v[i].PackHint(buf, x)
		buf[omega+i] = x
	}
	for ; x < uint8(omega); x++ {
		buf[x] = 0
	}
	return x
}

func (v Vec) UnPackHint(buf []byte, omega int) bool {
	index := uint8(0)
	for i := 0; i < len(v); i++ {
		if buf[omega+i] < index || buf[omega+i] > uint8(omega) {
			return false
		}
		first := index
		for j := index; j < buf[omega+i]; j++ {
			if index > first && buf[j-1] >= buf[j] {
				return false
			}
			v[i].AssignHint(j, buf)
		}
		index = buf[omega+i]
	}

	for i := int(index); i < omega; i++ {
		if buf[i] != 0 {
			return false
		}
	}
	return true
}

func (v Vec) InvNTT() {
	for i := 0; i < len(v); i++ {
		v[i].InvNTT()
	}
}

func (v Vec) NTT() {
	for i := 0; i < len(v); i++ {
		v[i].NTT()
	}
}

func (v Vec) Copy() Vec {
	u := make(Vec, len(v))
	for i := range v {
		u[i] = v[i]
	}
	return u
}

func (v Vec) ReduceWithModQ() {
	for i := 0; i < len(v); i++ {
		v[i].ReduceWithModQ()
	}
}
