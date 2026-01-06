package fips203

import (
	"bytes"
	"github.com/Deeptiman/forgekey/go/src/kem/internal/kyber/common"
	"github.com/Deeptiman/forgekey/go/src/kem/internal/kyber/cpapke"
	"github.com/Deeptiman/forgekey/go/src/sha3"
)

type PublicKey struct {
	pk  *cpapke.PublicKey
	hpk [common.SeedSize]byte
}

type PrivateKey struct {
	sk  *cpapke.PrivateKey
	pk  *cpapke.PublicKey
	hpk [common.SeedSize]byte
	z   [common.SeedSize]byte
}

type Protocol struct {
	cpa *cpapke.Kyber
}

func New(lvl cpapke.Level) *Protocol {
	return &Protocol{cpa: cpapke.WithKyberConfigs(lvl)}
}

func (f *Protocol) GenerateKeyPair(seed []byte, scheme cpapke.Level) (*PublicKey, *PrivateKey) {
	var seed2 [33]byte
	copy(seed2[:32], seed)
	seed2[32] = byte(f.cpa.K)

	cpa := cpapke.GenerateKeyPair(seed2[:], scheme)

	pk := &PublicKey{}
	sk := &PrivateKey{}

	pk.pk = cpa.GetPublicKey()
	sk.pk = cpa.GetPublicKey()
	sk.sk = cpa.GetPrivateKey()

	copy(sk.z[:], seed[32:])

	ppk := cpa.PackPublicKey()
	h := sha3.New256()
	h.Write(ppk[:])
	h.Read(sk.hpk[:])
	copy(pk.hpk[:], sk.hpk[:])
	return pk, sk
}

func (f *Protocol) UnPackPublicKey(keyBytes []byte) *PublicKey {
	f.cpa.UnPackPublicKey(keyBytes)
	var pk PublicKey
	pk.pk = f.cpa.GetPublicKey()

	h := sha3.New256()
	h.Write(keyBytes)
	h.Read(pk.hpk[:])

	return &pk
}

func (f *Protocol) UnPackPrivateKey(keyBytes []byte) *PrivateKey {
	var sk PrivateKey
	f.cpa.UnPackPrivateKey(keyBytes[:f.cpa.PrivateKeySize])
	sk.sk = f.cpa.GetPrivateKey()
	keyBytes = keyBytes[f.cpa.PrivateKeySize:]

	f.cpa.UnPackPublicKey(keyBytes[:f.cpa.PublicKeySize])
	sk.pk = f.cpa.GetPublicKey()

	var hpk [32]byte
	h := sha3.New256()
	h.Write(keyBytes[:f.cpa.PublicKeySize])
	h.Read(hpk[:])
	keyBytes = keyBytes[f.cpa.PublicKeySize:]

	copy(sk.hpk[:], keyBytes[:32])
	copy(sk.z[:], keyBytes[32:])

	if !bytes.Equal(hpk[:], sk.hpk[:]) {
		return nil
	}
	return &sk
}

func (p *PrivateKey) Equals(q *PrivateKey) bool {
	return p.sk.Equals(q.sk)
}

func (p *PublicKey) Equals(q *PublicKey) bool {
	return p.pk.Equals(q.pk)
}
