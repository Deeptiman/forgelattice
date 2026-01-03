package kyber

const (
	// N Kyber polynomial degree
	N = 256
	// Q Kyber modulus
	Q uint32 = 3329

	PolySize = 384

	// QInv Montgomery constants
	QInv   int32 = 62209 // qInv = q⁻¹ mod 2¹⁶
	R2modQ int32 = 1353  // R² mod Q

	// ModRedBound ....
	ModRedBound = 1 << 15

	// BarrettK16Mu Barrett constants
	// mu26 = floor(2²⁶ / Kyber_Q) = 20158.86
	// 20159 candidate selected as floor candidate because it fits perfectly with the computation.
	BarrettK16Mu int32 = 20159
)

var zetas = PrecomputeKyberZetas()

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

type Configs struct {
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
	Cfg Configs

	Pk PublicKey
	Sk PrivateKey
}

type PublicKey struct {
	rho [32]byte
	A   PolyMatrix
	T   PolyVec // transient accumulator
}

type PrivateKey struct {
	V PolyVec
	Z [32]byte
}

func ParamsFor(l Level) Params {
	switch l {
	case Level512:
		cfg := Configs{K: 2, Eta1: 3, Eta2: 2, Du: 10, Dv: 4, CiphertextSize: 768, PublicKeySize: 32 + l.K()*PolySize, PrivateKeySize: l.K() * PolySize}
		return Params{Cfg: cfg, Pk: PublicKey{A: NewPolyMatrix(l)}, Sk: PrivateKey{V: NewPolyVec(l)}}
	case Level768:
		cfg := Configs{K: 3, Eta1: 2, Eta2: 2, Du: 10, Dv: 4, CiphertextSize: 1088, PublicKeySize: 32 + l.K()*PolySize, PrivateKeySize: l.K() * PolySize}
		return Params{Cfg: cfg, Pk: PublicKey{A: NewPolyMatrix(l)}, Sk: PrivateKey{V: NewPolyVec(l)}}
	case Level1024:
		cfg := Configs{K: 4, Eta1: 2, Eta2: 2, Du: 11, Dv: 5, CiphertextSize: 1568, PublicKeySize: 32 + l.K()*PolySize, PrivateKeySize: l.K() * PolySize}
		return Params{Cfg: cfg, Pk: PublicKey{A: NewPolyMatrix(l)}, Sk: PrivateKey{V: NewPolyVec(l)}}
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
