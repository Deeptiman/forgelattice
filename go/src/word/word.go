package word

import "math/bits"

type Word interface {
	~int16 | ~uint32 | ~uint64
}

type Algorithm int

const (
	Kyber Algorithm = iota
	Dilithium
	Homomorphic
)

type Bits interface {
	~int16 | ~int32 | ~uint64
}

type BitProfile struct {
	Mode        Algorithm
	StorageBits int // 16 / 32 / 64
	AccumBits   int // 32 / 64 / 128
}

func InferBitProfile(q uint64, N int, mode Algorithm) BitProfile {
	bitWidth := bits.Len64(q - 1)

	var p BitProfile
	p.Mode = mode

	switch {
	case bitWidth <= 15:
		p.StorageBits = 16
	case bitWidth <= 31:
		p.StorageBits = 32
	default:
		p.StorageBits = 64
	}

	return BitProfile{}
}
