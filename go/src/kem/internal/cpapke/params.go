package cpapke

import (
	"github.com/Deeptiman/forgekey/go/src/kem/internal/common"
	"github.com/Deeptiman/forgekey/go/src/kem/internal/poly"
)

// PublicKey represents a Kyber CPA-PKE public key.
//
// NOTE:
//
//	The matrix A is not transmitted directly. The rho only serialized, and A is regenerated during
//
// unpacking.
type PublicKey struct {
	// rho: seed used to deterministically generate the public matrix A.
	rho [common.SeedSize]byte
	// a: public matrix A (generated from rho)
	a poly.Matrix
	// t: public vector t = A*s + e (stored in NTT domain).
	t poly.Vec // transient accumulator
}

// PrivateKey represents a Kyber CPA-PKE private key.
//
// The secret vector is sampled from a centred binomial distribution and stored in the NTT domain.
type PrivateKey struct {
	// s: secret vector (s)
	s poly.Vec
}

// Constants defines all cryptographic constants for a Kyber parameter set.
//
// These values fully determine the security and performance metrics of a Kyber instance.
type Constants struct {
	// Scheme parameters
	// K: Dimension of module lattice.
	K int
	// Q: Kyber prime modulus=3329.
	Q int16
	// N: Polynomial degree N=256
	N int

	// Noise
	// Eta1: Noise for secret and error vectors.
	Eta1 int
	// Eta2: Noise for encryption error vector.
	Eta2 int

	// Compression
	// Du: Compression bits for vector u.
	Du int
	// Dv: Compression bits for polynomial v.
	Dv int

	// Serialized Key Sizes (in bytes)
	PublicKeySize  int
	PrivateKeySize int
	CiphertextSize int
}

// Params represents a complete CPA-PKE parameterization.
type Params struct {
	Constants
	Name string
}

// Level represents a Kyber security level.
//
// Each level corresponds to a distinct security target and parameter set:
//
//   - Level512:  ~128-bit security
//   - Level768:  ~192-bit security
//   - Level1024: ~256-bit security
type Level int

const (
	Level512  Level = iota // Kyber-512
	Level768               // Kyber-768
	Level1024              // Kyber-1024
)

// String returns the canonical Kyber scheme name for the level.
func (l Level) String() string {
	switch l {
	case Level512:
		return "Kyber-512"
	case Level768:
		return "Kyber-768"
	case Level1024:
		return "Kyber-1024"
	default:
		panic("invalid kyber level")
	}
}

// ToLevel maps a ML-KEM scheme identifier to its underlying Kyber level.
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

// ParamsFor returns the Kyber CPA-PKE parameters for a given security level.
func ParamsFor(l Level) Params {
	switch l {
	case Level512, Level768, Level1024:
		return Params{Constants: l.WithConstants(), Name: l.String()}
	default:
		panic("invalid kyber level")
	}
}

// WithKyberConfigs constructs a fully initialized Kyber CPA-PKE instance for the given security level.
func WithKyberConfigs(l Level) *Kyber {
	p := ParamsFor(l)
	pk := &PublicKey{a: NewPolyMatrix(l)}
	sk := &PrivateKey{s: NewPolyVec(l)}
	return &Kyber{p, pk, sk}
}

// WithConstants returns the Kyber constants corresponds to the security level.
//
// These values are fixed by the Kyber specification and FIPS203. Any deviation will break interoperability
// and security.
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

// K returns the module rank for the given Kyber security level. Increasing K increases security by expanding the
// lattice dimension and raising the hardness of the underlying Module-LWE (Learning With Error) problem.
//
// The module rank K determines the dimensionality of the underlying module lattice and controls how many polynomials
// used to represent secrets, public keys and ciphertext components.
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

// NewPolyVec allocates a polynomial vector of dimension K appropriate for the given security level.
func NewPolyVec(level Level) poly.Vec {
	return make(poly.Vec, level.K())
}

// NewPolyMatrix allocates a KxK polynomial matrix appropriate for the given security level.
func NewPolyMatrix(level Level) poly.Matrix {
	K := level.K()
	m := make(poly.Matrix, K)
	for i := 0; i < K; i++ {
		m[i] = NewPolyVec(level)
	}
	return m
}
