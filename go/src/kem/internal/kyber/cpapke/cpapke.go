package cpapke

import (
	"crypto/sha3"
	"github.com/Deeptiman/forgekey/go/src/kem/internal/kyber/common"
	"github.com/Deeptiman/forgekey/go/src/kem/internal/kyber/poly"
)

// Kyber key-generation steps [PublicKey, PrivateKey]
// 1. Generate 32-bytes random seed
// 2. Expand seed with SHAKE256
// 3. Split the seed into seedA and seedS
// 4. Deterministically generate public matrix A from seedA
// 5. Sample secret vector s using CBD (Centered Binomial Distribution)
// 6. Sample noise vector e using CBD (Centered Binomial Distribution)
// 7. Compute [A * s + e (mod Q)]
// 8. Output public key (seedA, t)
// 9. Output secret key s
// 10. Encrypt random  32-bytes with PublicKey.
// 11. Decrypt the ciphertext with PrivateKey.

const (
	N        = common.N
	Q        = common.Q
	PolySize = common.PolySize
)

type Kyber struct {
	Params
	pk *PublicKey
	sk *PrivateKey
}

func (p *Kyber) GenerateKeyPair(seed []byte) *Kyber {
	seedA, sigma := common.ExpandSeed(seed[:])

	copy(p.pk.rho[:], seedA[:32])
	p.generatePublicMatrixA(&p.pk.rho, false) // A

	for i := 0; i < p.K; i++ {
		p.sk.v[i].SampleNoise(sigma[:], uint8(i), p.Eta1) // S
	}

	for i := 0; i < p.K; i++ {
		p.sk.v[i].NTT()
	}

	for i := 0; i < p.K; i++ {
		p.sk.v[i].Reduce()
	}

	eh := make(poly.Vec, p.K)
	for i := 0; i < p.K; i++ {
		eh[i].SampleNoise(sigma[:], uint8(p.K)+uint8(i), p.Eta1) // e
	}

	for i := 0; i < p.K; i++ {
		eh[i].NTT()
	}

	p.pk.t = make(poly.Vec, p.K)
	for i := 0; i < p.K; i++ {
		var t poly.Poly
		publicMatrix := p.pk.a[i]
		secretVector := p.sk.v
		for j := 0; j < p.K; j++ {
			t.MulConvolution(&publicMatrix[j], &secretVector[j])
		}
		p.pk.t[i].Add(t)
		p.pk.t[i].ToMont()
	}

	for i := 0; i < p.K; i++ {
		p.pk.t[i].Add(eh[i])
	}

	for i := 0; i < p.K; i++ {
		p.pk.t[i].Reduce()
	}

	p.Transpose()
	return &Kyber{p.Params, p.pk, p.sk}
}

func (p *Kyber) GetPublicKey() *PublicKey {
	return p.pk
}

func (p *Kyber) GetPrivateKey() *PrivateKey {
	return p.sk
}

func (p *Kyber) generatePublicMatrixA(rho *[32]byte, transpose bool) {
	// 1. Gather 32-bytes random numbers (rho).
	// 2. Shake it with 128-bit for each row & column and rho bytes.
	// 3. Apply rejection sampler for each iteration to collect 12-bits of buffer.
	// 4. Add it to the polynomial coefficients.
	// 5. Complete the loop to generate KxK matrix uniform within [0 ... Q)
	for x := 0; x < p.K; x++ {
		for y := 0; y < p.K; y++ {
			if transpose {
				p.pk.a[x][y].Uniform(rho, byte(x), byte(y))
			} else {
				p.pk.a[x][y].Uniform(rho, byte(y), byte(x))
			}
		}
	}
}

func (p *Kyber) Encrypt(ct, pt, seed []byte) {
	rh := make(poly.Vec, p.K)
	e1 := make(poly.Vec, p.K)
	var e2 poly.Poly

	// 1. Sample noise (r, e1, e2)
	for i := 0; i < p.K; i++ {
		rh[i].SampleNoise(seed, uint8(i), p.Eta1)
	}

	for i := 0; i < p.K; i++ {
		rh[i].NTT()
	}

	for i := 0; i < p.K; i++ {
		rh[i].Reduce()
	}

	for i := 0; i < p.K; i++ {
		e1[i].SampleNoise(seed, uint8(p.K)+uint8(i), p.Eta2)
	}
	e2.SampleNoise(seed, uint8(2*p.K), p.Eta2)

	// 2. u = A^T . r + e1
	u := make(poly.Vec, p.K)
	for i := 0; i < p.K; i++ {
		var tmp poly.Poly
		for j := 0; j < p.K; j++ {
			tmp.MulConvolution(&p.pk.a[i][j], &rh[j])
		}
		u[i].Add(tmp)
	}

	for i := 0; i < p.K; i++ {
		u[i].Reduce()
	}

	for i := 0; i < p.K; i++ {
		u[i].InvNTT()
	}

	for i := 0; i < p.K; i++ {
		u[i].Add(e1[i])
	}

	// 3. v = t . r + e2 + m
	var v, m, tmp poly.Poly
	for i := 0; i < p.K; i++ {
		tmp.MulConvolution(&p.pk.t[i], &rh[i])
	}
	v.Add(tmp)
	v.Reduce()
	v.InvNTT()

	m.DecompressMessage(pt)
	v.Add(m)
	v.Add(e2)

	for i := 0; i < p.K; i++ {
		u[i].Reduce()
	}
	v.Reduce()

	// 4. Compress
	size := poly.CompressedPolySize(p.Du)
	for i := 0; i < p.K; i++ {
		u[i].Compress(ct[size*i:], p.Du)
	}
	v.Compress(ct[p.K*size:], p.Dv)
}

func (p *Kyber) GenerateSecretVectorNoise(seed []byte, nonce uint8) {
	for i := 0; i < p.K; i++ {
		switch p.Eta1 {
		case 2:
			p.sk.v[i].GenerateSecretVectorNoiseWithEta2(seed[:], nonce+uint8(i))
		case 3:
			p.sk.v[i].GenerateSecretVectorNoiseWithEta3(seed[:], nonce+uint8(i))
		}
	}
}

func (p *Kyber) Decrypt(pt []byte, ct []byte) {
	var u poly.Vec
	var v, m poly.Poly

	size := poly.CompressedPolySize(p.Du)
	u = make(poly.Vec, p.K)
	for i := 0; i < p.K; i++ {
		u[i].Decompress(ct[size*i:], p.Du)
	}
	v.Decompress(ct[p.K*size:], p.Dv)

	for i := 0; i < p.K; i++ {
		u[i].NTT()
	}

	var tmp poly.Poly
	for i := 0; i < p.K; i++ {
		tmp.MulConvolution(&p.sk.v[i], &u[i])
	}
	m.Add(tmp)
	m.Reduce()
	m.InvNTT()
	m.Sub(v)
	m.Reduce()
	m.CompressMessage(pt)
}

func (p *Kyber) PackPrivateKey() []byte {
	privateKeySize := p.PrivateKeySize + p.PublicKeySize + 64
	keyBytes := make([]byte, privateKeySize)
	offset := 0
	for i := 0; i < p.K; i++ {
		p.sk.v[i].Pack(keyBytes[offset:])
		offset += PolySize
	}

	// PublicKey
	pkBytes := p.PackPublicKey()
	copy(keyBytes[offset:], pkBytes)
	offset += len(pkBytes)

	// Hash(pk)
	h := sha3.Sum256(pkBytes)
	copy(keyBytes[offset:], h[:])
	offset += 32

	return keyBytes
}

func (p *Kyber) UnPackPrivateKey(keyBytes []byte) {
	p.sk.v = make(poly.Vec, p.K)
	offset := 0
	for i := 0; i < p.K; i++ {
		p.sk.v[i].UnPack(keyBytes[offset:])
		offset += PolySize
	}
}

func (p *Kyber) PackPublicKey() []byte {
	keyBytes := make([]byte, p.PublicKeySize)
	for i := 0; i < p.K; i++ {
		p.pk.t[i].Pack(keyBytes[PolySize*i:])
	}
	copy(keyBytes[p.K*PolySize:], p.pk.rho[:])
	return keyBytes
}

func (p *Kyber) PrivateKeyReduce() {
	for i := 0; i < p.K; i++ {
		p.sk.v[i].Reduce()
	}
}

func (p *Kyber) UnPackPublicKey(keyBytes []byte) {
	p.pk.t = make(poly.Vec, p.K)
	offset := 0
	for i := 0; i < p.K; i++ {
		p.pk.t[i].UnPack(keyBytes[offset:])
		offset += PolySize
	}
	//p.PublicKeyNormalize()
	copy(p.pk.rho[:], keyBytes[p.K*PolySize:])
	p.generatePublicMatrixA(&p.pk.rho, true)
}

func (p *Kyber) PublicKeyReduce() {
	for i := 0; i < p.K; i++ {
		p.pk.t[i].Reduce()
	}
}

func (p *Kyber) PrivateKeyNormalize() {
	for i := 0; i < p.K; i++ {
		p.sk.v[i].Reduce()
	}
}

func (p *Kyber) PublicKeyNormalize() {
	for i := 0; i < p.K; i++ {
		p.pk.t[i].Reduce()
	}
}

func (p *Kyber) Transpose() {
	for i := 0; i < p.K-1; i++ {
		for j := i + 1; j < p.K; j++ {
			t := p.pk.a[i][j]
			p.pk.a[i][j] = p.pk.a[j][i]
			p.pk.a[j][i] = t
		}
	}
}

func (p *Kyber) Scheme() string {
	return p.Name
}
