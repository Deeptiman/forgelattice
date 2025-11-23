package modred

type Algorithm string

type ModRed struct {
	// Kyber constants.
	KyberQ            int32
	KyberQInv         int32
	KyberR2modQ       int32
	KyberBarrettK16Mu int32

	// Dilithium constants.
	DilithiumQ    uint64
	DilithiumQInv uint32

	// Homomorphic Q ~60-bit modulus.
	HomomorphicQ uint64

	montConstants   montgomeryConstants
	barrettConstant barrettConstant
}

type barrettConstant struct {
	mu32 uint64
	mu64 uint64
}

type montgomeryConstants struct {
	qInv uint64 // qInv = -q^{-1} mod 2^64
	r2   uint64 // R^2 mod q
}
