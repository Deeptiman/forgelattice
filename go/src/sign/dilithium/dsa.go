package sign

import (
	"github.com/Deeptiman/forgelattice/go/src/sign/dilithium/internal/common"
	"github.com/Deeptiman/forgelattice/go/src/sign/dilithium/internal/dsa"
	"github.com/Deeptiman/forgelattice/go/src/sign/dilithium/mldsa/fips204"
)

type API interface {
	Scheme() string
	GenerateKeyPair(seed [common.SeedSize]byte) (fips204.PublicKey, fips204.PrivateKey)
	Sign(secretBytes []byte, msgBytes []byte, rnd [32]byte) []byte
	Verify(publicBytes, signatureBytes []byte, msgBytes []byte) bool

	MarshalPublicKey(pk fips204.PublicKey) []byte
	MarshalPrivateKey(sk fips204.PrivateKey) []byte
	UnmarshalPublicKey(buf []byte) fips204.PublicKey
	UnmarshalPrivateKey(buf []byte) fips204.PrivateKey

	IsPublicKeyValid(srcPk, targetPk fips204.PublicKey) bool
	IsPrivateKeyValid(srcSk, targetSk fips204.PrivateKey) bool
}

type DSA struct {
	protocol API
}

func WithFIPS204(l dsa.Level) API {
	return &DSA{protocol: fips204.New(l)}
}

func (d *DSA) GenerateKeyPair(seed [common.SeedSize]byte) (fips204.PublicKey, fips204.PrivateKey) {
	return d.protocol.GenerateKeyPair(seed)
}

func (d *DSA) Sign(secretBytes []byte, msgBytes []byte, rnd [32]byte) []byte {
	return d.protocol.Sign(secretBytes, msgBytes, rnd)
}

func (d *DSA) Verify(publicBytes, signatureBytes []byte, msgBytes []byte) bool {
	return d.protocol.Verify(publicBytes, signatureBytes, msgBytes)
}

func (d *DSA) MarshalPublicKey(pk fips204.PublicKey) []byte {
	return d.protocol.MarshalPublicKey(pk)
}

func (d *DSA) MarshalPrivateKey(sk fips204.PrivateKey) []byte {
	return d.protocol.MarshalPrivateKey(sk)
}

func (d *DSA) UnmarshalPublicKey(buf []byte) fips204.PublicKey {
	return d.protocol.UnmarshalPublicKey(buf)
}

func (d *DSA) UnmarshalPrivateKey(buf []byte) fips204.PrivateKey {
	return d.protocol.UnmarshalPrivateKey(buf)
}

func (d *DSA) IsPublicKeyValid(srcPk, targetPk fips204.PublicKey) bool {
	return d.protocol.IsPublicKeyValid(srcPk, targetPk)
}

func (d *DSA) IsPrivateKeyValid(srcSk, targetSk fips204.PrivateKey) bool {
	return d.protocol.IsPrivateKeyValid(srcSk, targetSk)
}

func (d *DSA) Scheme() string {
	return d.protocol.Scheme()
}
