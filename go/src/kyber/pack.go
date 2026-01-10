package kyber

import (
	"crypto/sha3"
	"encoding/hex"
)

func (p *Params) PackPrivateKey() []byte {
	privateKeySize := p.PrivateKeySize + p.PublicKeySize + 64
	keyBytes := make([]byte, privateKeySize)
	offset := 0
	for i := 0; i < p.K; i++ {
		p.Sk.V[i].Pack(keyBytes[offset:])
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

func (p *Params) UnPackPrivateKey(keyBytes []byte) *PrivateKey {
	p.Sk.V = make(PolyVec, p.K)
	offset := 0
	for i := 0; i < p.K; i++ {
		p.Sk.V[i].UnPack(keyBytes[offset:])
		offset += PolySize
	}
	return &p.Sk
}

func (p *Params) PackPublicKey() []byte {
	keyBytes := make([]byte, p.PublicKeySize)
	for i := 0; i < p.K; i++ {
		p.Pk.T[i].Pack(keyBytes[PolySize*i:])
	}
	copy(keyBytes[p.K*PolySize:], p.Pk.rho[:])
	return keyBytes
}

func (p *Params) PackPublicKeyKEM(keyBytes []byte) []byte {
	for i := 0; i < p.K; i++ {
		p.Pk.T[i].Pack(keyBytes[PolySize*i:])
	}
	copy(keyBytes[p.K*PolySize:], p.Pk.rho[:])
	return keyBytes
}

func (p *Params) UnPackPublicKey(keyBytes []byte) *PublicKey {
	p.Pk.T = make(PolyVec, p.K)
	offset := 0
	for i := 0; i < p.K; i++ {
		p.Pk.T[i].UnPack(keyBytes[offset:])
		offset += PolySize
	}
	p.PublicKeyNormalize()
	copy(p.Pk.rho[:], keyBytes[p.K*PolySize:])
	p.GeneratePublicMatrixA(&p.Pk.rho, true)
	return &p.Pk
}

func (p *Params) PrivateKeyNormalize() {
	for i := 0; i < p.K; i++ {
		p.Sk.V[i].Normalize()
	}
}

func (p *Params) PublicKeyNormalize() {
	for i := 0; i < p.K; i++ {
		p.Pk.T[i].Normalize()
	}
}

func (pk *PrivateKey) ToString(keyBytes []byte) string {
	return hex.EncodeToString(keyBytes)
}

func (pk *PublicKey) ToString(keyBytes []byte) string {
	return hex.EncodeToString(keyBytes)
}
