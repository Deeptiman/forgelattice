package modred

const (
	// Kyber modulus
	Kyber  Algorithm = "PQC_Kyber"
	KyberQ           = 3329

	// Kyber Montgomery constants
	KyberQInv   int32 = 62209 // qInv = q⁻¹ mod 2¹⁶
	KyberR2modQ int32 = 1353  // R² mod Q

	// Kyber Barrett constants
	// mu26 = floor(2²⁶ / Kyber_Q) = 20158.86
	// 20159 candidate selected as floor candidate because it fits perfectly with the computation.
	KyberBarrettK16Mu int32 = 20159

	// Dilithium modulus
	Dilithium  Algorithm = "PQC_Dilithium"
	DilithiumQ uint64    = 8380417

	// Homomorphic ...
	Homomorphic Algorithm = "Homomorphic_Encryption"
	HEQ         uint64    = 0x0FFFFFFFFFFFFFFB // < 2^60 (homomorphic ~60-bit modulus)
)
