package kyber

import (
	"crypto/subtle"
	"fmt"
	"github.com/Deeptiman/forgekey/go/src/sha3"
)

type PublicKeyKEM struct {
	pk  *PublicKey
	hpk [32]byte
}

type PrivateKeyKEM struct {
	sk  *PrivateKey
	pk  *PublicKey
	hpk [32]byte
	z   [32]byte
}

func (p *Params) GenerateKEMKeyPair(seed []byte) (*PublicKeyKEM, *PrivateKeyKEM) {
	publicKeyKEM := &PublicKeyKEM{}
	privateKeyKEM := &PrivateKeyKEM{}

	// z <-- Random_Bytes(32)
	// (pk sk) := Kyber.CPAPKE.KeyGen()
	// sk := (sk'||pk||H(pk)||z)

	var seed2 [33]byte
	copy(seed2[:32], seed)
	seed2[32] = byte(p.K)

	publicKey, privateKey := p.GenerateKeyPair(seed2[:])
	publicKeyKEM.pk = publicKey
	privateKeyKEM.pk = publicKey
	privateKeyKEM.sk = privateKey
	copy(privateKeyKEM.z[:], seed[32:])

	ppk := p.PackPublicKey()
	h := sha3.New256()
	h.Write(ppk[:])
	h.Read(privateKeyKEM.hpk[:])
	copy(publicKeyKEM.hpk[:], privateKeyKEM.hpk[:])
	return publicKeyKEM, privateKeyKEM
}

func (pk *PublicKeyKEM) EncapsulateTo(p *Params, ct, ss []byte, seed []byte) {
	var m [32]byte
	copy(m[:], seed)

	// (K', r) = G(m ‖ H(pk))
	var kr [64]byte
	g := sha3.New512()
	g.Write(m[:])
	g.Write(pk.hpk[:])
	g.Read(kr[:])

	// c = Kyber.CPAPKE.Enc(pk, m, r)
	p.Encrypt(ct, m[:], kr[32:])

	copy(ss, kr[:32])
}

func (pk *PublicKeyKEM) Encapsulate(p *Params, ct, ss []byte, seed []byte) {
	var m [32]byte
	copy(m[:], seed)

	// (K', r) = G(m||H(pk))
	var kr [64]byte
	g := sha3.New512()
	g.Write(m[:])
	g.Write(pk.hpk[:])
	g.Read(kr[:])

	// c = KYBER.CPAPKE.Enc(pk, m, r)
	p.Encrypt(ct, m[:], kr[32:])

	// K := KDF(k'||H(c))
	copy(ss, kr[:32])
}

func (sk *PrivateKeyKEM) Decapsulate(p *Params, ss, ct []byte) {
	// m' = Kyber.CPAPKE.Dec(sk, ct)
	var m [32]byte
	p.Decrypt(m[:], ct)

	// coins' = H(pk || m')
	var kr2 [64]byte
	g := sha3.New512()
	g.Write(m[:])
	g.Write(sk.hpk[:])
	g.Read(kr2[:])

	// Re-encrypt
	ct2 := make([]byte, len(ct))
	p.Encrypt(ct2, m[:], kr2[32:])

	var ss2 [32]byte

	// Compute shared secret in case of rejection: ss₂ = PRF(z ‖ c)
	prf := sha3.NewShake256()
	prf.Write(sk.z[:])
	prf.Write(ct[:p.CiphertextSize])
	prf.Read(ss2[:])
	fmt.Println("ss2 = ", ss2)

	// Set ss2 to the real shared secret if c = c'.
	subtle.ConstantTimeCopy(
		subtle.ConstantTimeCompare(ct, ct2[:]),
		ss2[:],
		kr2[:32],
	)

	copy(ss[:], ss2[:])
}
