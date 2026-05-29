package fips203

import (
	"bytes"
	"crypto/subtle"
	"github.com/Deeptiman/forgelattice/crypto/kem/kyber/internal/common"
	"github.com/Deeptiman/forgelattice/crypto/kem/kyber/internal/cpapke"
	"github.com/Deeptiman/forgelattice/crypto/sha3"
)

// New initializes an ML-KEM protocol instance for a given Kyber security level.
//
// Kyber Security Level:
//   - cpapke.Level512
//   - cpapke.Level768
//   - cpapke.Level1024
func New(lvl cpapke.Level) *Protocol {
	return &Protocol{cpa: cpapke.WithKyberConfigs(lvl)}
}

// GenerateKeyPair deterministically generates an ML-KEM keypair from a seed.
//
// FIPS 203 requirement:
//
//	The seed MUST be extended with one byte encoding the Kyber parameter K to ensure domain separation
//
// between Kyber security-levels.
//
// seed layout:
//
//	seed[0...31] --> CPA key generation seed.
//	seed[32...63] ---> z (decapsulation fallback secret).
func (f *Protocol) GenerateKeyPair(seed []byte) (*PublicKey, *PrivateKey) {
	var seed2 [33]byte
	copy(seed2[:common.SeedSize], seed)
	// Domain-separated seed: seed || K
	seed2[common.SeedSize] = byte(f.cpa.K)

	cpa := f.cpa.GenerateKeyPair(seed2[:])

	pk := &PublicKey{}
	sk := &PrivateKey{}

	pk.pk = cpa.GetPublicKey()
	sk.pk = cpa.GetPublicKey()
	sk.sk = cpa.GetPrivateKey()

	// Copy fallback seed to z
	copy(sk.z[:], seed[common.SeedSize:])

	// Compute hpk = H(Pack(pk))
	ppk := cpa.PackPublicKey(pk.pk)
	h := sha3.New256()
	_, _ = h.Write(ppk[:])
	h.Read(sk.hpk[:])
	copy(pk.hpk[:], sk.hpk[:])
	return pk, sk
}

// Encapsulate performs ML-KEM encapsulation to generate a ciphertext and shared-secret key.
func (f *Protocol) Encapsulate(pk *PublicKey, seed []byte) (ct, ss []byte) {
	var m [common.SeedSize]byte
	copy(m[:], seed)

	ct = make([]byte, f.cpa.CiphertextSize)
	ss = make([]byte, common.SeedSize)

	// (K', r) = G(m||H(pk))
	var kr [64]byte
	g := sha3.New512()
	_, _ = g.Write(m[:])
	_, _ = g.Write(pk.hpk[:])
	g.Read(kr[:])

	// c = KYBER.CPAPKE.Enc(pk, m, r)
	f.cpa.Encrypt(ct, m[:], kr[common.SeedSize:])

	// ss = K'
	copy(ss, kr[:common.SeedSize])

	return ct, ss
}

// Decapsulate performs ML-KEM decapsulation to validated the input ciphertext and shared-secret key
// is returned in both success and failure scenarios.
func (f *Protocol) Decapsulate(sk *PrivateKey, ct []byte) []byte {
	var m [common.SeedSize]byte
	// m' = CPAPKE.Decrypt(sk, ct)
	f.cpa.Decrypt(m[:], ct)

	// (K', r') = G(m'||H(pk))
	var kr [64]byte
	g := sha3.New512()
	_, _ = g.Write(m[:])
	_, _ = g.Write(sk.hpk[:])
	g.Read(kr[:])

	// K' = kr[:common.SeedSize:]
	// r' = kr[common.SeedSize:]
	//
	// Re-encrypt to verify if hash of publicKey matches with input ciphertext.
	ct1 := make([]byte, f.cpa.CiphertextSize)
	// ct' = CPAPKE.Encrypt(pk, m', r')
	f.cpa.Encrypt(ct1, m[:], kr[common.SeedSize:])

	var ss [common.SeedSize]byte
	ok := subtle.ConstantTimeCompare(ct, ct1)
	if ok == 1 {
		// if ct == ct': ss = K'
		copy(ss[:], kr[:common.SeedSize])
	} else {
		// secret fallback: ss = PRF(z||ct)
		prf := sha3.NewShake256()
		_, _ = prf.Write(sk.z[:])
		_, _ = prf.Write(ct[:f.cpa.CiphertextSize])
		prf.Read(ss[:])
	}

	return ss[:]
}

// UnPackPublicKey reconstructs an ML-KEM public key from the input key bytes.
func (f *Protocol) UnPackPublicKey(keyBytes []byte) *PublicKey {
	f.cpa.UnPackPublicKey(keyBytes)
	var pk PublicKey
	pk.pk = f.cpa.GetPublicKey()

	// public-key hash is recomputed and stored for later use.
	h := sha3.New256()
	_, _ = h.Write(keyBytes)
	h.Read(pk.hpk[:])

	return &pk
}

// UnPackPrivateKey reconstructs an ML-KEM private key from input key bytes.
//
// It verifies the integrity by recomputing H(pk) and comparing it to the stored value.
func (f *Protocol) UnPackPrivateKey(keyBytes []byte) *PrivateKey {
	var sk PrivateKey

	// 1. Unpack CPA private key.
	f.cpa.UnPackPrivateKey(keyBytes[:f.cpa.PrivateKeySize])
	sk.sk = f.cpa.GetPrivateKey()
	keyBytes = keyBytes[f.cpa.PrivateKeySize:]

	// 2. Unpack CPA public key.
	f.cpa.UnPackPublicKey(keyBytes[:f.cpa.PublicKeySize])
	sk.pk = f.cpa.GetPublicKey()

	// Recompute the public key hash.
	var hpk [common.SeedSize]byte
	h := sha3.New256()
	_, _ = h.Write(keyBytes[:f.cpa.PublicKeySize])
	h.Read(hpk[:])
	keyBytes = keyBytes[f.cpa.PublicKeySize:]

	copy(sk.hpk[:], keyBytes[:common.SeedSize])
	copy(sk.z[:], keyBytes[common.SeedSize:])

	// Compares the hash with previously stored hash of public key.
	if !bytes.Equal(hpk[:], sk.hpk[:]) {
		// Integrity failed.
		return nil
	}

	return &sk
}

func (f *Protocol) PackPrivateKey(sk *PrivateKey) []byte {
	return f.cpa.PackPrivateKey(sk.sk)
}

func (f *Protocol) PackPublicKey(pk *PublicKey) []byte {
	return f.cpa.PackPublicKey(pk.pk)
}

// Scheme returns the standardized scheme name.
func (f *Protocol) Scheme() string {
	return "ML-KEM-" + f.cpa.Scheme()
}
