package modred

func NewModRed(q uint64, algo Algorithm) *ModRed {
	r := &ModRed{}
	switch algo {
	case Kyber:
		r.KyberQ = KyberQ
		r.KyberQInv = KyberQInv
		r.KyberR2modQ = KyberR2modQ
		r.KyberBarrettK16Mu = KyberBarrettK16Mu
	case Dilithium:
		r.DilithiumQ = DilithiumQ
		r.DilithiumQInv = computeDilithiumRedConstant(r.DilithiumQ)
	case Homomorphic:
		if q == 0 {
			r.HomomorphicQ = HEQ
		} else {
			r.HomomorphicQ = q
		}
		r.montConstants = computeMontgomeryConstants(r.HomomorphicQ)
		r.barrettConstant = computeBarrettRedConstant(r.HomomorphicQ)
	}
	return r
}
