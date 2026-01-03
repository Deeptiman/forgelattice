package kyber

import (
	"crypto/sha3"
	"encoding/hex"
	"strings"
)

func (p *Params) PackPrivateKey() []byte {
	privateKeySize := p.Cfg.PrivateKeySize + p.Cfg.PublicKeySize + 64
	keyBytes := make([]byte, privateKeySize)
	offset := 0
	for i := 0; i < p.Cfg.K; i++ {
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

	p.Sk.Z, _ = GenerateRandomBytes(nil)
	copy(keyBytes[offset:], p.Sk.Z[:])

	return keyBytes
}

func (p *Params) UnPackPrivateKey(privateKeyBytes []byte) *PrivateKey {
	keyBytes, _ := hex.DecodeString(strings.TrimPrefix(hex.EncodeToString(privateKeyBytes), "0x"))

	var pk PrivateKey
	pk.V = make(PolyVec, p.Cfg.K)
	offset := 0
	for i := 0; i < p.Cfg.K; i++ {
		pk.V[i].UnPack(keyBytes[offset:])
		offset += PolySize
	}
	offset += p.Cfg.PublicKeySize
	offset += 32

	copy(pk.Z[:], keyBytes[offset:offset+32])

	p.PrivateKeyNormalize()
	return &pk
}

func (p *Params) PackPublicKey() []byte {
	keyBytes := make([]byte, p.Cfg.PublicKeySize)
	for i := 0; i < p.Cfg.K; i++ {
		p.Pk.T[i].Pack(keyBytes[PolySize*i:])
	}
	copy(keyBytes[p.Cfg.K*PolySize:], p.Pk.rho[:])
	return keyBytes
}

func (p *Params) UnPackPublicKey(publicKeyBytes []byte) *PublicKey {
	keyBytes, _ := hex.DecodeString(strings.TrimPrefix(hex.EncodeToString(publicKeyBytes), "0x"))

	var pk PublicKey
	pk.T = make(PolyVec, p.Cfg.K)
	offset := 0
	for i := 0; i < p.Cfg.K; i++ {
		pk.T[i].UnPack(keyBytes[offset:])
		offset += PolySize
	}
	copy(pk.rho[:], keyBytes[p.Cfg.K*PolySize:])
	p.PublicKeyNormalize()
	return &pk
}

func (p *Params) PrivateKeyNormalize() {
	for i := 0; i < p.Cfg.K; i++ {
		p.Sk.V[i].Normalize()
	}
}

func (p *Params) PublicKeyNormalize() {
	for i := 0; i < p.Cfg.K; i++ {
		p.Pk.T[i].Normalize()
	}
}

func (pk *PrivateKey) ToString(keyBytes []byte) string {
	return hex.EncodeToString(keyBytes)
}

func (pk *PublicKey) ToString(keyBytes []byte) string {
	return hex.EncodeToString(keyBytes)
}
