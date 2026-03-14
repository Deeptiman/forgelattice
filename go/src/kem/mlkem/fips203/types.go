package fips203

import (
	"github.com/Deeptiman/forgekey/go/src/kem/internal/common"
	"github.com/Deeptiman/forgekey/go/src/kem/internal/cpapke"
)

// PublicKey represents an ML-KEM public key.
type PublicKey struct {
	// pk: the underlying Kyber CPAPKE primitive public key.
	pk *cpapke.PublicKey
	// hpk: SHA3-256 hash of the packed CPA public key.
	hpk [common.SeedSize]byte
}

// PrivateKey represents an ML-KEM private key.
type PrivateKey struct {
	// sk: Kyber CPAPKE primitive private key.
	sk *cpapke.PrivateKey
	// pk: Kyber CPAPKE primitive publick key.
	pk *cpapke.PublicKey
	// hpk: SHA3-256 hash of the packed CPA public key.
	hpk [common.SeedSize]byte
	// z: secret fallback value used during key-derivation, if decapsulation fails.
	z [common.SeedSize]byte
}

// Protocol binds a concrete Kyber CPAPKE instance into the ML-KEM (FIPS203) construction.
type Protocol struct {
	cpa *cpapke.Kyber
}
