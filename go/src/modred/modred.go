package modred

type Reduction[T any, X any] interface {
	KyberInt | DilithiumInt | HEInt
	MontgomeryMul(a, b T) X
	BarrettRedWith16bit(x T) X
	BarrettRedWith32bit(x T) X
	BarrettRedWith64bit(x T) X
}

type (
	KyberInt     int32
	DilithiumInt int32
	HEInt        struct {
		Q    uint64
		QInv uint64

		montConstants   montgomeryConstants
		barrettConstant barrettConstant
	}
)

type ModConfig[T any, X any, R Reduction[T, X]] struct {
	// Homomorphic Q ~60-bit modulus.
	HomomorphicQ uint64

	montConstants   montgomeryConstants
	barrettConstant barrettConstant

	// Reduction method execution
	Red R
}

type barrettConstant struct {
	mu32 uint64
	mu64 uint64
}

type montgomeryConstants struct {
	qInv uint64 // qInv = -q^{-1} mod 2^64
	r2   uint64 // R^2 mod q
}

func NewModDirective[T any, X any, R Reduction[T, X]](r R) *ModConfig[T, X, R] {
	return &ModConfig[T, X, R]{Red: r}
}
