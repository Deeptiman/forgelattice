package common

const (
	// N Kyber polynomial degree
	N = 256
	// Q Kyber modulus
	Q uint32 = 3329

	SeedSize = 32

	MaxBitRate = 168

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
