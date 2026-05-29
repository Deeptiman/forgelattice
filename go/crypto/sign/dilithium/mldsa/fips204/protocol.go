package fips204

import (
	"github.com/Deeptiman/forgelattice/go/crypto/sign/dilithium/internal/common"
	"github.com/Deeptiman/forgelattice/go/crypto/sign/dilithium/internal/dsa"
)

type Protocol struct {
	dsa *dsa.Dilithium
}

func New(lvl string) *Protocol {
	return &Protocol{dsa: dsa.WithDilithiumConfigs(dsa.ToLevel(lvl))}
}

func (d *Protocol) GenerateKeyPair(seed [common.SeedSize]byte) (PublicKey, PrivateKey) {
	return d.dsa.GenerateKeyPair(seed)
}

func (d *Protocol) Sign(secretBytes []byte, msgBytes []byte, rnd [32]byte) []byte {
	return d.dsa.Sign(secretBytes, msgBytes, rnd)
}

func (d *Protocol) Verify(publicBytes, signatureBytes []byte, msgBytes []byte) bool {
	return d.dsa.Verify(publicBytes, signatureBytes, msgBytes)
}

func (d *Protocol) Scheme() string {
	return d.dsa.Scheme()
}

func (d *Protocol) UnmarshalPublicKey(buf []byte) PublicKey {
	return d.dsa.UnmarshalPublicKey(buf)
}

func (d *Protocol) UnmarshalPrivateKey(buf []byte) PrivateKey {
	return d.dsa.UnmarshalPrivateKey(buf)
}

func (d *Protocol) MarshalPublicKey(pk PublicKey) []byte {
	return d.dsa.MarshalPublicKey(pk)
}

func (d *Protocol) MarshalPrivateKey(sk PrivateKey) []byte {
	return d.dsa.MarshalPrivateKey(sk)
}

func (d *Protocol) IsPublicKeyValid(srcPk, targetPk PublicKey) bool {
	return d.dsa.IsPublicKeyValid(srcPk, targetPk)
}

func (d *Protocol) IsPrivateKeyValid(srcSk, targetSk PrivateKey) bool {
	return d.dsa.IsPrivateKeyValid(srcSk, targetSk)
}
