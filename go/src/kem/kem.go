package kem

import (
	"github.com/Deeptiman/forgekey/go/src/kem/internal/kyber/cpapke"
	"github.com/Deeptiman/forgekey/go/src/kem/mlkem/fips203"
)

type API interface {
	Name() string
	GenerateKeyPair(seed []byte) (*fips203.PublicKey, *fips203.PrivateKey)
	Encapsulate(pk *fips203.PublicKey) (ct []byte, ss []byte)
	Decapsulate(sk *fips203.PrivateKey, ct []byte) (ss []byte, err error)
}

type KEM struct {
	protocol *fips203.Protocol
	level    cpapke.Level
}

func New(lvl cpapke.Level) API {
	return &KEM{level: lvl, protocol: fips203.New(lvl)}
}

func (k *KEM) GenerateKeyPair(seed []byte) (*fips203.PublicKey, *fips203.PrivateKey) {
	return k.protocol.GenerateKeyPair(seed[:], k.level)
}

func (k *KEM) Encapsulate(pk *fips203.PublicKey) (ct []byte, ss []byte) {
	return nil, nil
}

func (k *KEM) Decapsulate(sk *fips203.PrivateKey, ct []byte) (ss []byte, err error) {
	return nil, nil
}

func (k *KEM) Name() string {
	return k.level.String()
}
