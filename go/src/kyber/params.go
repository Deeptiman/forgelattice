package kyber

const (
	// N Kyber polynomial degree
	N = 256
	// Q Kyber modulus
	Q uint32 = 3329

	// QInv Montgomery constants
	QInv   int32 = 62209 // qInv = q⁻¹ mod 2¹⁶
	R2modQ int32 = 1353  // R² mod Q

	// BarrettK16Mu Barrett constants
	// mu26 = floor(2²⁶ / Kyber_Q) = 20158.86
	// 20159 candidate selected as floor candidate because it fits perfectly with the computation.
	BarrettK16Mu int32 = 20159
)

type Level int

const (
	Level512  Level = iota // Kyber-512
	Level768               // Kyber-768
	Level1024              // Kyber-1024
)

func (which Level) String() string {
	switch which {
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

type Poly [N]int16

type PolyVec []Poly

type PolyMatrix []PolyVec

type Mat PolyMatrix

type Params struct {
	K    int
	Eta  int
	Zeta [128]int16
	Pk   PublicKey
	Sk   PrivateKey
}

type PublicKey struct {
	rho [32]byte
	A   PolyMatrix
}

type PrivateKey struct {
	V PolyVec
}

func ParamsFor(level Level) Params {
	switch level {
	case Level512:
		return Params{K: 2, Eta: 2, Zeta: PrecomputeKyberZetas(), Pk: PublicKey{A: NewPolyMatrix(level)}, Sk: PrivateKey{V: NewPolyVec(level)}}
	case Level768:
		return Params{K: 3, Eta: 3, Zeta: PrecomputeKyberZetas(), Pk: PublicKey{A: NewPolyMatrix(level)}, Sk: PrivateKey{V: NewPolyVec(level)}}
	case Level1024:
		return Params{K: 4, Eta: 3, Zeta: PrecomputeKyberZetas(), Pk: PublicKey{A: NewPolyMatrix(level)}, Sk: PrivateKey{V: NewPolyVec(level)}}
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

func NewPolyVec(level Level) PolyVec {
	return make(PolyVec, level.K())
}

func NewPolyMatrix(level Level) PolyMatrix {
	K := level.K()
	m := make(PolyMatrix, K)
	for i := 0; i < K; i++ {
		m[i] = NewPolyVec(level)
	}
	return m
}
