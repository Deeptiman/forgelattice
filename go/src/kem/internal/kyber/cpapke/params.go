package cpapke

import (
	"encoding/hex"
	"github.com/Deeptiman/forgekey/go/src/kem/internal/kyber/common"
	"github.com/Deeptiman/forgekey/go/src/kem/internal/kyber/poly"
)

type PublicKey struct {
	rho [common.SeedSize]byte
	a   poly.Matrix
	t   poly.Vec // transient accumulator
}

type PrivateKey struct {
	v poly.Vec
}

type Constants struct {
	// Scheme parameters
	K int
	Q int16
	N int

	// Noise
	Eta1 int
	Eta2 int

	// Compression
	Du int
	Dv int

	// Key Sizes
	PublicKeySize  int
	PrivateKeySize int
	CiphertextSize int
}

type Params struct {
	Constants
	Name string
}

type Level int

const (
	Level512  Level = iota // Kyber-512
	Level768               // Kyber-768
	Level1024              // Kyber-1024
)

func (l Level) String() string {
	switch l {
	case Level512:
		return "Kyber-512"
	case Level768:
		return "Kyber-768"
	case Level1024:
		return "Kyber-1024"
	default:
		return ""
	}
}

func ToLevel(algorithm string) Level {
	switch algorithm {
	case "ML-KEM-512":
		return Level512
	case "ML-KEM-768":
		return Level768
	case "ML-KEM-1024":
		return Level1024
	default:
		panic("invalid kyber level")
	}

}

func ParamsFor(l Level) Params {
	switch l {
	case Level512, Level768, Level1024:
		return Params{Constants: l.WithConstants(), Name: l.String()}
	default:
		panic("invalid kyber level")
	}
}

func WithKyberConfigs(l Level) *Kyber {
	p := ParamsFor(l)
	pk := &PublicKey{a: NewPolyMatrix(l)}
	sk := &PrivateKey{v: NewPolyVec(l)}
	return &Kyber{p, pk, sk}
}

func (l Level) WithConstants() Constants {
	switch l {
	case Level512:
		return Constants{
			K:              2,
			Eta1:           3,
			Eta2:           2,
			Du:             10,
			Dv:             4,
			CiphertextSize: 768,
			PublicKeySize:  32 + l.K()*common.PolySize,
			PrivateKeySize: l.K() * common.PolySize,
		}
	case Level768:
		return Constants{
			K:              3,
			Eta1:           2,
			Eta2:           2,
			Du:             10,
			Dv:             4,
			CiphertextSize: 1088,
			PublicKeySize:  32 + l.K()*common.PolySize,
			PrivateKeySize: l.K() * common.PolySize,
		}
	case Level1024:
		return Constants{
			K:              4,
			Eta1:           2,
			Eta2:           2,
			Du:             11,
			Dv:             5,
			CiphertextSize: 1568,
			PublicKeySize:  32 + l.K()*common.PolySize,
			PrivateKeySize: l.K() * common.PolySize,
		}
	default:
		panic("invalid kyber level")
	}
}

func (l Level) K() int {
	switch l {
	case Level512:
		return 2
	case Level768:
		return 3
	case Level1024:
		return 4
	default:
		panic("invalid Kyber level")
	}
}

func NewPolyVec(level Level) poly.Vec {
	return make(poly.Vec, level.K())
}

func NewPolyMatrix(level Level) poly.Matrix {
	K := level.K()
	m := make(poly.Matrix, K)
	for i := 0; i < K; i++ {
		m[i] = NewPolyVec(level)
	}
	return m
}

func ToString(keyBytes []byte) string {
	return hex.EncodeToString(keyBytes)
}
