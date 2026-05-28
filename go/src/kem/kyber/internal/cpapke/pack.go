package cpapke

import (
	"github.com/Deeptiman/forgelattice/go/src/kem/kyber/internal/poly"
)

// PackPrivateKey serializes the CPA-PKE private key.
func (p *Kyber) PackPrivateKey() []byte {
	keyBytes := make([]byte, p.PrivateKeySize)
	offset := 0
	for i := 0; i < p.K; i++ {
		p.sk.s[i].Pack(keyBytes[offset:])
		offset += PolySize
	}
	return keyBytes
}

// UnPackPrivateKey deserializes a Kyber private key by unpacking the secret vector (v).
func (p *Kyber) UnPackPrivateKey(keyBytes []byte) {
	p.sk.s = make(poly.Vec, p.K)
	offset := 0
	for i := 0; i < p.K; i++ {
		p.sk.s[i].UnPack(keyBytes[offset:])
		offset += PolySize
	}
}

// PackPublicKey serializes the public key into the Kyber spec format.
func (p *Kyber) PackPublicKey() []byte {
	keyBytes := make([]byte, p.PublicKeySize)
	for i := 0; i < p.K; i++ {
		p.pk.t[i].Pack(keyBytes[PolySize*i:])
	}
	copy(keyBytes[p.K*PolySize:], p.pk.rho[:])
	return keyBytes
}

// UnPackPublicKey deserializes a Kyber public key and regenerates the public matrix A deterministically
// from rho.
func (p *Kyber) UnPackPublicKey(keyBytes []byte) {
	p.pk.t = make(poly.Vec, p.K)
	offset := 0
	for i := 0; i < p.K; i++ {
		p.pk.t[i].UnPack(keyBytes[offset:])
		offset += PolySize
	}
	copy(p.pk.rho[:], keyBytes[p.K*PolySize:])
	p.generatePublicMatrixA(&p.pk.rho, true)
}
