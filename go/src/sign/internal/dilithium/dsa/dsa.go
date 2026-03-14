package dsa

import (
	"fmt"
	"github.com/Deeptiman/forgekey/go/src/sha3"
	"github.com/Deeptiman/forgekey/go/src/sign/internal/dilithium/common"
	"github.com/Deeptiman/forgekey/go/src/sign/internal/dilithium/poly"
)

type Dilithium struct {
	Params
	pk *PublicKey
	sk *PrivateKey
}

func NewDilithium(l Level) *Dilithium {
	params := ParamFor(l)
	pk := &PublicKey{
		A:  NewPolyMatrix(params.K, params.L),
		t1: NewPolyVec(params.K),
	}
	sk := &PrivateKey{
		s1: NewPolyVec(params.L),
		s2: NewPolyVec(params.K),
		t0: NewPolyVec(params.K),
		A:  NewPolyMatrix(params.K, params.L),
	}
	return &Dilithium{params, pk, sk}
}

func (d *Dilithium) GenerateKeyPair(seed [common.SeedSize]byte) (*PublicKey, *PrivateKey) {
	var (
		keyGenSeed [128]byte
		secretSeed [64]byte
		pk         PublicKey
		sk         PrivateKey
	)

	h := sha3.NewShake256()
	_, _ = h.Write(seed[:])
	_, _ = h.Write([]byte{byte(d.K), byte(d.L)})
	h.Read(keyGenSeed[:])

	copy(pk.rho[:], keyGenSeed[:32])
	copy(secretSeed[:], keyGenSeed[32:96])
	copy(sk.seed[:], secretSeed[:])
	copy(sk.key[:], keyGenSeed[96:])
	copy(sk.rho[:], pk.rho[:])

	d.sk.rho = sk.rho
	d.sk.seed = sk.seed
	d.sk.key = sk.key
	d.pk.rho = pk.rho

	d.ExpandA(pk.rho)
	d.pk.A = d.sk.A

	for i := uint16(0); i < d.L; i++ {
		d.sk.s1[i].RejectionBoundPoly(&secretSeed, d.Eta, i)
	}

	for i := uint16(0); i < d.K; i++ {
		d.sk.s2[i].RejectionBoundPoly(&secretSeed, d.Eta, i+d.L)
	}

	d.sk.s1NTT = d.sk.s1
	for i := uint16(0); i < d.L; i++ {
		d.sk.s1NTT[i].NTT()
	}

	d.sk.s2NTT = d.sk.s2
	for i := uint16(0); i < d.K; i++ {
		d.sk.s2NTT[i].NTT()
	}

	// t <--- NTT⁻¹(A ∘ NTT(s₁)) + s₂
	t := make(poly.Vec, d.K)
	for i := uint16(0); i < d.K; i++ {
		vecA := d.sk.A[i]
		var temp poly.Poly
		for j := uint16(0); j < d.L; j++ {
			polyA := vecA[j]
			polyS1 := d.sk.s1NTT[j]
			temp.ReducePolyWithMontgomery(&polyA, &polyS1)
			t[i].Add(temp)
		}
		t[i].ReduceLe2Q()
		t[i].InvNTT()
	}

	for i := uint16(0); i < d.K; i++ {
		t[i].Add(d.sk.s2[i])
	}

	for i := uint16(0); i < d.K; i++ {
		t[i].ReduceWithModQ()
	}

	for i := uint16(0); i < d.K; i++ {
		t[i].Power2Round(&d.sk.t0[i], &d.pk.t1[i])
	}

	d.sk.t0NTT = d.sk.t0
	for i := uint16(0); i < d.K; i++ {
		d.sk.t0NTT[i].NTT()
	}

	d.pk.t1Encode = make([]byte, common.PolyT1PackSize*d.K)
	offset := 0
	for i := uint16(0); i < d.K; i++ {
		d.pk.t1[i].PackPublicKeyT1(d.pk.t1Encode[offset:])
		offset += common.PolyT1PackSize
	}

	pkBytes := make([]byte, d.PublicKeySize)
	copy(pkBytes[:32], d.pk.rho[:])
	copy(pkBytes[32:], d.pk.t1Encode[:])

	h.Reset()
	_, _ = h.Write(pkBytes[:])
	h.Read(d.sk.tr[:])

	d.pk.tr = &d.sk.tr

	return d.pk, d.sk
}

func (d *Dilithium) ExpandA(seed [common.SeedSize]byte) {
	for i := uint16(0); i < d.K; i++ {
		for j := uint16(0); j < d.L; j++ {
			d.sk.A[i][j].RejectionSampling(&seed, (i<<8)+j)
		}
	}
}

func (sk *PrivateKey) GetPublicKey(K, L uint16) *PublicKey {
	pk := &PublicKey{
		rho: sk.rho,
		A:   sk.A,
		t1:  NewPolyVec(K),
		tr:  &sk.tr,
	}
	t := make(poly.Vec, K)
	for i := uint16(0); i < K; i++ {
		vecA := sk.A[i]
		var temp poly.Poly
		for j := uint16(0); j < L; j++ {
			polyA := vecA[j]
			polyS1 := sk.s1NTT[j]
			temp.ReducePolyWithMontgomery(&polyA, &polyS1)
			t[i].Add(temp)
		}
		t[i].ReduceLe2Q()
		t[i].InvNTT()
	}

	for i := uint16(0); i < K; i++ {
		t[i].Add(sk.s2[i])
	}

	for i := uint16(0); i < K; i++ {
		t[i].ReduceWithModQ()
	}

	for i := uint16(0); i < K; i++ {
		t[i].Power2Round(&sk.t0[i], &pk.t1[i])
	}

	pk.t1Encode = make([]byte, common.PolyT1PackSize*K)
	offset := 0
	for i := uint16(0); i < K; i++ {
		pk.t1[i].PackPublicKeyT1(pk.t1Encode[offset:])
		offset += common.PolyT1PackSize
	}

	return pk
}

func (pk *PublicKey) Equal(K uint16, other *PublicKey) bool {
	for i := uint16(0); i < K; i++ {
		fmt.Println("Equal ==> ", pk.rho == other.rho && pk.t1[i] == other.t1[i])
		fmt.Println(" --> ", pk.rho)
		fmt.Println(" --> ", other.rho)
		fmt.Println(" --> ", pk.t1[i])
		fmt.Println(" --> ", other.t1[i])
		if pk.rho != other.rho && pk.t1[i] != other.t1[i] {
			return false
		}
	}
	return true
}
