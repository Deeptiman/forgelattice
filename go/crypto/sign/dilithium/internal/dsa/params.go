package dsa

import (
	"github.com/Deeptiman/forgelattice/go/crypto/sign/dilithium/internal/common"
	"github.com/Deeptiman/forgelattice/go/crypto/sign/dilithium/internal/poly"
)

type PublicKey struct {
	rho      [32]byte
	t1       poly.Vec // with dimension K.
	t1Encode []byte
	A        poly.Mat
	tr       *[common.TRSize]byte
}

type PrivateKey struct {
	rho  [32]byte
	key  [32]byte
	seed [32]byte
	s1   poly.Vec // with dimension L.
	s2   poly.Vec // with dimension K.
	t0   poly.Vec // with dimension K.

	s1NTT poly.Vec
	s2NTT poly.Vec
	t0NTT poly.Vec

	tr [common.TRSize]byte
	A  poly.Mat
}

type Constant struct {
	// K: dimension of the public vector.
	K int
	// L : dimension of the private vector.
	L int
	// Q: Dilithium prime modulus = 8380417.
	Q int
	// N: Polynomial Degree N = 256
	N int

	// D: number of low bits dropped in power2round(t -> t1, t0)
	// Fixed at 13-bits for all levels.
	// How many low bits are discarded when splitting t into t1 (public) and t0 (secret).
	D int

	// Tau(𝜏): exact hamming weight of challenge polynomial c (number of ±1 coefficients)
	// Tau=39 means exactly 39 places in c are ±1, rest are 0.
	Tau int

	// Eta(𝜂): bound on coefficients of s1 and s2 (CBD dilithium)
	// s1, s2 coeffs ∈ {−𝜂, …, 𝜂}
	// 𝜂=2 --> 5 possible values, strict tight noise.
	// 𝜂=4 --> 9 possible values, slightly more noise.
	Eta           int
	DoubleEtaBits int

	// Beta 𝛽=𝜏⋅𝜂 : rejection bound for z = y + c.s1
	Beta int

	// Gamma1(𝛾₁): The random y numbers between -Gamma1 and +Gamma1.
	Gamma1 int

	// Gamma1Bits: bits needed to encode one coefficient of y/z
	Gamma1Bits int

	// Gamma2(𝛾₂): bound on low-order part after decomposition.
	// w = w₁.(2.𝛾₂) + w₀ with |w₀| ≤ γ₂
	Gamma2 int

	// Omega(ω): maximum number of non-zero entries allowed in hint vector h.
	Omega int

	// Alpha(α): maximum width to fit widest possible step size for the high part (a1).
	Alpha int

	// ML-DSA-44:
	// -> PrivateKeySize = 2560
	// -> PublicKeySize = 1312
	// -> SignatureSize = 2420
	//
	// ML-DSA-65:
	//
	// -> PrivateKeySize = 4032
	// -> PublicKeySize = 1952
	// -> SignatureSize = 3309
	//
	// ML-DSA-87:
	//
	// -> PrivateKeySize = 4896
	// -> PublicKeySize = 2592
	// -> SignatureSize = 4627
	PublicKeySize  int
	PrivateKeySize int
	SignatureSize  int

	PolyT0Size       int
	PolyT1Size       int
	PolyLeqEtaSize   int
	PolyW1PackedSize int
	PolyLeGamma1Size int
	CTildeSize       int
}

type Params struct {
	Constant
	Name string
}

type Level int

const (
	Level2 = iota
	Level3
	Level5
)

func (l Level) String() string {
	switch l {
	case Level2:
		return "ML-DSA-44"
	case Level3:
		return "ML-DSA-65"
	case Level5:
		return "ML-DSA-87"
	default:
		panic("invalid dilithium security level")
	}
}

func ToLevel(algorithm string) Level {
	switch algorithm {
	case "ML-DSA-44":
		return Level2
	case "ML-DSA-65":
		return Level3
	case "ML-DSA-87":
		return Level5
	default:
		panic("invalid dilithium signer algorithm")
	}
}

func (l Level) K() uint16 {
	switch l {
	case Level2:
		return 4
	case Level3:
		return 6
	case Level5:
		return 8
	default:
		panic("invalid dilithium security level")
	}
}

func (l Level) L() int {
	switch l {
	case Level2:
		return 4
	case Level3:
		return 5
	case Level5:
		return 7
	default:
		panic("invalid dilithium security level")
	}
}

func ParamsFor(l Level) Params {
	switch l {
	case Level2, Level3, Level5:
		return Params{l.WithConstants(), l.String()}
	default:
		panic("invalid dilithium security level")
	}
}

func WithDilithiumConfigs(l Level) *Dilithium {
	params := ParamsFor(l)
	return &Dilithium{Params: params}
}

// NewPolyVec allocates a polynomial vector of dimension K appropriate for the given security level.
func NewPolyVec(dim int) poly.Vec {
	return make(poly.Vec, dim)
}

// NewPolyMatrix allocates a KxK polynomial matrix appropriate for the given security level.
func NewPolyMatrix(K, L int) poly.Mat {
	m := make(poly.Mat, K)
	for i := 0; i < K; i++ {
		m[i] = make(poly.Vec, K)
		for j := 0; j < L; j++ {
			m[i][j] = poly.Poly{}
		}
	}
	return m
}

func (l Level) WithConstants() Constant {
	switch l {
	case Level2:
		return Constant{
			K:                4,
			L:                4,
			Q:                8380417,
			N:                256,
			D:                13,
			Eta:              2,
			DoubleEtaBits:    3,
			Tau:              39,
			Beta:             78,
			Gamma1:           1 << 17,
			Gamma1Bits:       17,
			Gamma2:           95232, // (Q-1)/88
			Omega:            80,
			Alpha:            190464, // α = 2 * Gamma2
			PublicKeySize:    1312,
			PrivateKeySize:   2560,
			SignatureSize:    2420,
			PolyLeqEtaSize:   96, // (common.N * DoubleEtaBits) / 8
			PolyW1PackedSize: (common.N * (common.QBits - 17)) / 8,
			PolyLeGamma1Size: ((17 + 1) * common.N) / 8,
			CTildeSize:       32,
		}
	case Level3:
		return Constant{
			K:                6,
			L:                5,
			Q:                8380417,
			N:                256,
			D:                13,
			Eta:              4,
			DoubleEtaBits:    4,
			Tau:              49,
			Beta:             196,
			Gamma1:           1 << 19,
			Gamma1Bits:       19,
			Gamma2:           261888, // (Q-1)/32
			Omega:            55,
			Alpha:            523776, // α = 2 * Gamma2
			PublicKeySize:    1952,
			PrivateKeySize:   4032,
			SignatureSize:    3309,
			PolyLeqEtaSize:   128, // (common.N * DoubleEtaBits) / 8
			PolyW1PackedSize: (common.N * (common.QBits - 19)) / 8,
			PolyLeGamma1Size: ((19 + 1) * common.N) / 8,
			CTildeSize:       48,
		}
	case Level5:
		return Constant{
			K:                8,
			L:                7,
			Q:                8380417,
			N:                256,
			D:                13,
			Eta:              2,
			DoubleEtaBits:    3,
			Tau:              60,
			Beta:             120,
			Gamma1:           1 << 19,
			Gamma1Bits:       19,
			Gamma2:           261888, // (Q-1)/32
			Omega:            75,
			Alpha:            523776, // α = 2 * Gamma2
			PublicKeySize:    2592,
			PrivateKeySize:   4896,
			SignatureSize:    4627,
			PolyLeqEtaSize:   96, // (common.N * DoubleEtaBits) / 8
			PolyW1PackedSize: (common.N * (common.QBits - 19)) / 8,
			PolyLeGamma1Size: ((19 + 1) * common.N) / 8,
			CTildeSize:       64,
		}
	default:
		panic("invalid dilithium security level")
	}
}
