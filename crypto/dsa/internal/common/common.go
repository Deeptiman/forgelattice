package common

import "github.com/Deeptiman/forgelattice/crypto/dsa/internal/mathutils"

const (
	N                     = 256
	Q                     = 8380417 // 2²³ - 2¹³ + 1
	QBits                 = 23
	D                     = 13
	SeedSize              = 32
	R2modQ         uint32 = 4193792 // = (256)⁻¹ R² mod q, where R=2³²
	ROver256              = 41978   // (256)⁻¹ R²
	DoubleEtaBits         = 3       // 3-bits/coeffs for s1/s2 encoding (works for 𝜂=2, 𝜂=4)
	PolyT1PackSize        = (N * (QBits - D)) / 8
	PolyT0PackSize        = (N * D) / 8
	PolyLe16Size          = N / 2
	TRSize                = 64
)

var QInv = (^mathutils.ModInverse32(uint32(Q))) + 1
