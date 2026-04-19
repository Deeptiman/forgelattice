package dsa

import (
	"bytes"
	"crypto/subtle"
	"github.com/Deeptiman/forgekey/go/src/sha3"
	"github.com/Deeptiman/forgekey/go/src/sign/internal/dilithium/common"
	"github.com/Deeptiman/forgekey/go/src/sign/internal/dilithium/poly"
)

type Dilithium struct {
	Params
	pk *PublicKey
	sk *PrivateKey
}

type signature struct {
	z    poly.Vec
	hint poly.Vec
	c    []byte
}

func (d *Dilithium) GenerateKeyPair(seed [common.SeedSize]byte) (*PublicKey, *PrivateKey) {
	var (
		keyGenSeed [128]byte
		secretSeed [64]byte
		pk         PublicKey
		sk         PrivateKey
	)

	pk = PublicKey{
		A:  NewPolyMatrix(d.K, d.L),
		t1: NewPolyVec(d.K),
	}
	sk = PrivateKey{
		s1: NewPolyVec(d.L),
		s2: NewPolyVec(d.K),
		t0: NewPolyVec(d.K),
		A:  NewPolyMatrix(d.K, d.L),
	}

	h := sha3.NewShake256()
	_, _ = h.Write(seed[:])
	_, _ = h.Write([]byte{byte(d.K), byte(d.L)})
	h.Read(keyGenSeed[:])

	copy(pk.rho[:], keyGenSeed[:32])
	copy(secretSeed[:], keyGenSeed[32:96])
	copy(sk.seed[:], secretSeed[:])
	copy(sk.key[:], keyGenSeed[96:])
	copy(sk.rho[:], pk.rho[:])

	sk.A.ExpandA(pk.rho, d.K, d.L)
	copy(pk.A, sk.A)

	sk.s1.ExpandS1(&secretSeed, d.Eta)
	sk.s2.ExpandS2(&secretSeed, d.Eta, d.L)

	sk.s1NTT = make(poly.Vec, d.L)
	sk.s1NTT = sk.s1.Copy()
	sk.s1NTT.NTT()

	sk.s2NTT = make(poly.Vec, d.K)
	sk.s2NTT = sk.s2.Copy()
	sk.s2NTT.NTT()

	// t <--- NTT⁻¹(A ∘ NTT(s₁)) + s₂
	t := make(poly.Vec, d.K)
	for i := 0; i < d.K; i++ {
		var temp poly.Poly
		t[i] = poly.Poly{}
		for j := 0; j < d.L; j++ {
			temp.DotWithMontgomery(&sk.A[i][j], &sk.s1NTT[j])
			t[i].Add(&temp, &t[i])
		}
		t[i].Le2QUsingCIRCL()
		t[i].InvNTT()
	}

	th := t.Add(sk.s2)
	th.ReduceWithModQ()
	th.Power2Round(sk.t0, pk.t1)

	sk.t0NTT = make(poly.Vec, d.K)
	for i := range sk.t0 {
		sk.t0NTT[i] = sk.t0[i]
	}
	sk.t0NTT.NTT()

	pk.t1Encode = make([]byte, common.PolyT1PackSize*d.K)
	pk.t1.PackPublicKeyT1(pk.t1Encode)

	pkBytes := make([]byte, d.PublicKeySize)
	copy(pkBytes[:32], pk.rho[:])
	copy(pkBytes[32:], pk.t1Encode[:])

	h.Reset()
	_, _ = h.Write(pkBytes[:])
	h.Read(sk.tr[:])

	pk.tr = &sk.tr

	return &pk, &sk
}

func (d *Dilithium) GetPublicKey(K, L int, sk *PrivateKey) *PublicKey {
	pk := &PublicKey{
		rho: sk.rho,
		A:   sk.A,
		t1:  NewPolyVec(K),
		tr:  &sk.tr,
	}
	t := make(poly.Vec, K)
	for i := 0; i < K; i++ {
		var temp poly.Poly
		t[i] = poly.Poly{}
		for j := 0; j < L; j++ {
			temp.DotWithMontgomery(&sk.A[i][j], &sk.s1NTT[j])
			t[i].Add(&temp, &t[i])
		}
		t[i].Le2QUsingCIRCL()
		t[i].InvNTT()
	}

	th := t.Add(sk.s2)
	th.ReduceWithModQ()
	th.Power2Round(sk.t0, pk.t1)

	pk.t1Encode = make([]byte, common.PolyT1PackSize*K)
	pk.t1.PackPublicKeyT1(pk.t1Encode)

	return pk
}

func (d *Dilithium) Sign(secretBytes []byte, msgBytes []byte, rnd [32]byte) []byte {
	var mu, rhop [64]byte

	sk := d.UnmarshalPrivateKey(secretBytes)

	// compute mu
	h := sha3.NewShake256()
	_, _ = h.Write(sk.tr[:])
	_, _ = h.Write(msgBytes[:])
	h.Read(mu[:])

	h.Reset()

	// compute private random seed
	_, _ = h.Write(sk.key[:])
	_, _ = h.Write(rnd[:])
	_, _ = h.Write(mu[:])
	h.Read(rhop[:])

	// initial counters
	var counter = 0
	var k = 0

	for counter <= d.PolyLeGamma1Size {
		counter++

		y := d.ExpandMask(&rhop, k)
		k += d.L

		yNTT := y.Copy()
		yNTT.NTT()

		// w <--- NTT⁻¹(A ∘ NTT(y))
		w := make(poly.Vec, d.K)
		for i := 0; i < d.K; i++ {
			var temp poly.Poly
			w[i] = poly.Poly{}
			for j := 0; j < d.L; j++ {
				temp.DotWithMontgomery(&sk.A[i][j], &yNTT[j])
				w[i].Add(&temp, &w[i])
			}
			w[i].Le2QUsingCIRCL()
			w[i].InvNTT()
		}

		w.ReduceLe2QModQ()
		w0, w1 := w.Decompose(d.Alpha)

		w1PackedBytes := w1.Encode(d.PolyW1PackedSize, d.Gamma1Bits)

		h.Reset()

		c := make([]byte, d.CTildeSize)
		_, _ = h.Write(mu[:])
		_, _ = h.Write(w1PackedBytes[:])
		h.Read(c[:])

		var ch poly.Poly
		ch.SampleInBall(d.Tau, c[:])
		ch.NTT()

		cs1 := make(poly.Vec, d.L)
		for i := 0; i < d.L; i++ {
			cs1[i].DotWithMontgomery(&ch, &sk.s1NTT[i])
			cs1[i].InvNTT()
		}
		cs1.ReduceWithModQ()

		cs2 := make(poly.Vec, d.K)
		for i := 0; i < d.K; i++ {
			cs2[i].DotWithMontgomery(&ch, &sk.s2NTT[i])
			cs2[i].InvNTT()
		}
		cs2.ReduceWithModQ()

		z := y.Add(cs1)
		z.ReduceWithModQ()

		r0 := w0.Sub(cs2)
		r0.ReduceWithModQ()

		zExceeds := z.ExceedsBound(uint32(d.Gamma1 - d.Beta))
		r0Exceeds := r0.ExceedsBound(uint32(d.Gamma2 - d.Beta))
		if zExceeds || r0Exceeds {
			continue
		}

		ct0 := make(poly.Vec, d.K)
		for i := 0; i < d.K; i++ {
			ct0[i].DotWithMontgomery(&ch, &sk.t0NTT[i])
			ct0[i].InvNTT()
		}
		ct0.ReduceWithModQ()

		if ct0.ExceedsBound(uint32(d.Gamma2)) {
			continue
		}

		r1 := r0.Add(ct0)
		r1.ReduceLe2QModQ()
		hint := make(poly.Vec, d.K)
		count := hint.MakeHint(d.Gamma2, r1, w1)

		if count > d.Omega {
			continue
		}

		return d.sigEncode(c, z, hint)
	}
	return nil
}

func (d *Dilithium) Verify(publicBytes, signatureBytes []byte, msgBytes []byte) bool {
	pk := d.UnmarshalPublicKey(publicBytes)
	if pk == nil {
		return false
	}

	sig := d.sigDecode(signatureBytes)
	if sig == nil {
		return false
	}

	var mu [64]byte
	h := sha3.NewShake256()
	_, _ = h.Write(pk.tr[:])
	_, _ = h.Write(msgBytes[:])
	h.Read(mu[:])

	var ch poly.Poly
	ch.SampleInBall(d.Tau, sig.c[:])
	ch.NTT()

	zNTT := make(poly.Vec, len(sig.z))
	zNTT = sig.z.Copy()
	zNTT.NTT()

	Az := make(poly.Vec, d.K)
	for i := 0; i < d.K; i++ {
		var temp poly.Poly
		Az[i] = poly.Poly{}
		for j := 0; j < d.L; j++ {
			temp.DotWithMontgomery(&pk.A[i][j], &zNTT[j])
			Az[i].Add(&temp, &Az[i])
		}
		Az[i].Le2QUsingCIRCL()
	}

	t12D := pk.t1.MultiplyBy2ToD()
	t12D.NTT()

	ct12D := make(poly.Vec, d.K)
	for i := 0; i < d.K; i++ {
		ct12D[i].DotWithMontgomery(&ch, &t12D[i])
	}

	Azct12D := Az.Sub(ct12D)
	Azct12D.Le2QUsingCIRCL()
	Azct12D.InvNTT()
	Azct12D.ReduceLe2QModQ()

	w0, w1 := Azct12D.Decompose(d.Alpha)
	sig.hint.UseHint(d.Gamma2, w0, w1)

	w1Packed := w1.Encode(d.PolyW1PackedSize, d.Gamma1Bits)

	h.Reset()
	c := make([]byte, d.CTildeSize)
	_, _ = h.Write(mu[:])
	_, _ = h.Write(w1Packed[:])
	h.Read(c[:])

	return bytes.Compare(sig.c, c) == 0
}

func (d *Dilithium) sigEncode(c []byte, z, hint poly.Vec) []byte {
	buf := make([]byte, d.SignatureSize)
	copy(buf[:], c[:])
	z.SigPack(buf[d.CTildeSize:], d.Gamma1Bits, d.PolyLeGamma1Size)
	hint.PackHint(buf[d.CTildeSize+d.L*d.PolyLeGamma1Size:], d.Omega)
	return buf
}

func (d *Dilithium) sigDecode(buf []byte) *signature {
	if len(buf) > d.SignatureSize {
		return nil
	}
	c := make([]byte, d.CTildeSize)
	copy(c[:], buf[:])

	z := make(poly.Vec, d.L)
	z.SigUnPack(buf[d.CTildeSize:], d.Gamma1Bits, d.PolyLeGamma1Size)

	if z.ExceedsBound(uint32(d.Gamma1) - uint32(d.Beta)) {
		return nil
	}

	hint := make(poly.Vec, d.K)
	if !hint.UnPackHint(buf[d.CTildeSize+d.L*d.PolyLeGamma1Size:], d.Omega) {
		return nil
	}
	return &signature{z, hint, c}
}

func (d *Dilithium) ExpandMask(seed *[64]byte, k int) poly.Vec {
	y := make(poly.Vec, d.L)
	for i := 0; i < d.L; i++ {
		nonce := k + i
		y[i].DeriveUniformLeGamma1(d.Gamma1Bits, d.PolyLeGamma1Size, seed, uint16(nonce))
	}
	return y
}

func (d *Dilithium) Scheme() string {
	return d.Name
}

func (d *Dilithium) IsPublicKeyValid(srcPk, targetPk *PublicKey) bool {
	return srcPk.Equal(d.K, targetPk)
}

func (d *Dilithium) IsPrivateKeyValid(srcSk, targetSk *PrivateKey) bool {
	return srcSk.Equal(d.K, d.L, targetSk)
}

func (pk *PublicKey) Equal(K int, other *PublicKey) bool {
	for i := 0; i < K; i++ {
		if pk.rho != other.rho && pk.t1[i] != other.t1[i] {
			return false
		}
	}
	return true
}

func (sk *PrivateKey) Equal(K, L int, other *PrivateKey) bool {
	ret := subtle.ConstantTimeCompare(sk.rho[:], other.rho[:]) &
		subtle.ConstantTimeCompare(sk.key[:], other.key[:]) &
		subtle.ConstantTimeCompare(sk.tr[:], other.tr[:])

	acc := uint32(0)
	for i := 0; i < L; i++ {
		acc |= sk.s1[i].Accumulator(&other.s1[i])
	}
	for i := 0; i < K; i++ {
		acc |= sk.s2[i].Accumulator(&other.s2[i])
		acc |= sk.t0[i].Accumulator(&other.t0[i])
	}
	return (ret & subtle.ConstantTimeEq(int32(acc), 0)) == 1
}
