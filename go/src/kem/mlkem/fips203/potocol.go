package fips203

import (
	"bytes"
	"crypto/subtle"
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

func (f *Protocol) GenerateKeyPair(seed []byte) (*PublicKey, *PrivateKey) {
	var seed2 [33]byte
	copy(seed2[:common.SeedSize], seed)
	seed2[common.SeedSize] = byte(f.cpa.K)

	cpa := f.cpa.GenerateKeyPair(seed2[:])

	pk := &PublicKey{}
	sk := &PrivateKey{}

	pk.pk = cpa.GetPublicKey()
	sk.pk = cpa.GetPublicKey()
	sk.sk = cpa.GetPrivateKey()

	copy(sk.z[:], seed[common.SeedSize:])

	ppk := cpa.PackPublicKey()
	h := sha3.New256()
	h.Write(ppk[:])
	h.Read(sk.hpk[:])
	copy(pk.hpk[:], sk.hpk[:])
	return pk, sk
}

func (f *Protocol) Encapsulate(pk *PublicKey, seed []byte) (ct, ss []byte) {
	var m [common.SeedSize]byte
	copy(m[:], seed)

	ct = make([]byte, f.cpa.CiphertextSize)
	ss = make([]byte, common.SeedSize)

	// (K', r) = G(m||H(pk))
	var kr [64]byte
	g := sha3.New512()
	g.Write(m[:])
	g.Write(pk.hpk[:])
	g.Read(kr[:])

	// c = KYBER.CPAPKE.Enc(pk, m, r)
	f.cpa.Encrypt(ct, m[:], kr[common.SeedSize:])

	// K := KDF(k'||H(c))
	copy(ss, kr[:common.SeedSize])

	return ct, ss
}

func (f *Protocol) Decapsulate(sk *PrivateKey, ct []byte) []byte {
	var m [common.SeedSize]byte
	f.cpa.Decrypt(m[:], ct)

	// coins' = H(pk || m')
	var kr2 [64]byte
	g := sha3.New512()
	g.Write(m[:])
	g.Write(sk.hpk[:])
	g.Read(kr2[:])

	// Re-encrypt to verify if hash of publicKey matches with input ciphertext.
	ct2 := make([]byte, f.cpa.CiphertextSize)
	f.cpa.Encrypt(ct2, m[:], kr2[common.SeedSize:])

	var ss [common.SeedSize]byte
	ok := subtle.ConstantTimeCompare(ct, ct2)
	if ok == 1 {
		copy(ss[:], kr2[:common.SeedSize])
	} else {
		// secret fallback and will append arbitrary bits {KDF(zH(c))}
		prf := sha3.NewShake256()
		prf.Write(sk.z[:])
		prf.Write(ct[:f.cpa.CiphertextSize])
		prf.Read(ss[:])
	}

	return ss[:]
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

	var hpk [common.SeedSize]byte
	h := sha3.New256()
	h.Write(keyBytes[:f.cpa.PublicKeySize])
	h.Read(hpk[:])
	keyBytes = keyBytes[f.cpa.PublicKeySize:]

	copy(sk.hpk[:], keyBytes[:common.SeedSize])
	copy(sk.z[:], keyBytes[common.SeedSize:])

	if !bytes.Equal(hpk[:], sk.hpk[:]) {
		return nil
	}
	return &sk
}

func (f *Protocol) Scheme() string {
	return "ML-KEM-" + f.cpa.Scheme()
}
