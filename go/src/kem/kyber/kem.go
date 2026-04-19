package kem

import (
	"github.com/Deeptiman/forgekey/go/src/kem/kyber/internal/cpapke"
	"github.com/Deeptiman/forgekey/go/src/kem/kyber/mlkem/fips203"
)

type API interface {
	Scheme() string
	GenerateKeyPair(seed []byte) (*fips203.PublicKey, *fips203.PrivateKey)
	Encapsulate(pk *fips203.PublicKey, seed []byte) (ct []byte, ss []byte)
	Decapsulate(sk *fips203.PrivateKey, ct []byte) []byte
	UnPackPublicKey(keyBytes []byte) *fips203.PublicKey
	UnPackPrivateKey(keyBytes []byte) *fips203.PrivateKey
}

type KEM struct {
	protocol API
}

func WithFIPS203(lvl cpapke.Level) API {
	return &KEM{protocol: fips203.New(lvl)}
}

func (k *KEM) GenerateKeyPair(seed []byte) (*fips203.PublicKey, *fips203.PrivateKey) {
	return k.protocol.GenerateKeyPair(seed[:])
}

func (k *KEM) Encapsulate(pk *fips203.PublicKey, seed []byte) (ct []byte, ss []byte) {
	return k.protocol.Encapsulate(pk, seed)
}

func (k *KEM) Decapsulate(sk *fips203.PrivateKey, ct []byte) []byte {
	return k.protocol.Decapsulate(sk, ct)
}

func (k *KEM) UnPackPublicKey(keyBytes []byte) *fips203.PublicKey {
	return k.protocol.UnPackPublicKey(keyBytes)
}

func (k *KEM) UnPackPrivateKey(keyBytes []byte) *fips203.PrivateKey {
	return k.protocol.UnPackPrivateKey(keyBytes)
}

func (k *KEM) Scheme() string {
	return k.protocol.Scheme()
}
