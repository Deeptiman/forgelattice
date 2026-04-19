package dsa

import (
	"github.com/Deeptiman/forgekey/go/src/sha3"
	"github.com/Deeptiman/forgekey/go/src/sign/dilithium/internal/common"
	"github.com/Deeptiman/forgekey/go/src/sign/dilithium/internal/poly"
)

func (d *Dilithium) MarshalPublicKey(pk *PublicKey) []byte {
	buf := make([]byte, d.PublicKeySize)
	copy(buf[:32], pk.rho[:])
	copy(buf[32:], pk.t1Encode[:])
	return buf
}

func (d *Dilithium) UnmarshalPublicKey(buf []byte) *PublicKey {
	var pk PublicKey
	pk.t1Encode = make([]byte, common.PolyT1PackSize*d.K)
	copy(pk.rho[:], buf[:32])
	copy(pk.t1Encode[:], buf[32:])

	pk.t1 = make(poly.Vec, d.K)
	pk.t1.UnpackT1(pk.t1Encode[:], d.K)
	pk.A = NewPolyMatrix(d.K, d.L)
	pk.A.ExpandA(pk.rho, d.K, d.L)

	// tr = CRH(ρ ‖ t1) = CRH(pk)
	pk.tr = new([common.TRSize]byte)
	h := sha3.NewShake256()
	_, _ = h.Write(buf[:])
	h.Read(pk.tr[:])
	return &pk
}

func (d *Dilithium) MarshalPrivateKey(sk *PrivateKey) []byte {
	buf := make([]byte, d.PrivateKeySize)
	copy(buf[:32], sk.rho[:])
	copy(buf[32:64], sk.key[:])
	copy(buf[64:64+common.TRSize], sk.tr[:])
	offset := 64 + common.TRSize
	sk.s1.PackLeqEta(buf[offset:], d.L, uint32(d.Eta), d.DoubleEtaBits, d.PolyLeqEtaSize)
	offset += d.PolyLeqEtaSize * d.L
	sk.s2.PackLeqEta(buf[offset:], d.K, uint32(d.Eta), d.DoubleEtaBits, d.PolyLeqEtaSize)
	offset += d.PolyLeqEtaSize * d.K
	sk.t0.PackT0(buf[offset:], d.K)
	return buf
}

func (d *Dilithium) UnmarshalPrivateKey(buf []byte) *PrivateKey {
	var sk PrivateKey
	copy(sk.rho[:], buf[:32])
	copy(sk.key[:], buf[32:64])
	copy(sk.tr[:], buf[64:64+common.TRSize])

	offset := 64 + common.TRSize
	sk.s1 = make(poly.Vec, d.L)
	sk.s1.UnpackLeqEta(buf[offset:], d.L, uint32(d.Eta), d.DoubleEtaBits, d.PolyLeqEtaSize)
	offset += d.PolyLeqEtaSize * d.L

	sk.s2 = make(poly.Vec, d.K)
	sk.s2.UnpackLeqEta(buf[offset:], d.K, uint32(d.Eta), d.DoubleEtaBits, d.PolyLeqEtaSize)
	offset += d.PolyLeqEtaSize * d.K

	sk.t0 = make(poly.Vec, d.K)
	sk.t0.UnpackT0(buf[offset:], d.K)

	sk.A = NewPolyMatrix(d.K, d.L)
	sk.A.ExpandA(sk.rho, d.K, d.L)
	sk.t0NTT = make(poly.Vec, d.K)
	sk.t0NTT = sk.t0.Copy()
	sk.t0NTT.NTT()

	sk.s1NTT = make(poly.Vec, d.L)
	sk.s1NTT = sk.s1.Copy()
	sk.s1NTT.NTT()

	sk.s2NTT = make(poly.Vec, d.K)
	sk.s2NTT = sk.s2.Copy()
	sk.s2NTT.NTT()
	return &sk
}

func (d *Dilithium) PackLeqEta(v poly.Vec, buf []byte) {
	offset := 0
	for i := 0; i < d.L; i++ {
		v[i].PackLeqEta(buf[offset:], uint32(d.Eta), d.DoubleEtaBits, d.PolyLeqEtaSize)
		offset += d.PolyLeqEtaSize
	}
}
