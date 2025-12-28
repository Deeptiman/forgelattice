package kyber

func (p *Poly) NTT(zetas [128]int16) {
	k := 0
	for subProblems := 2; subProblems <= N; subProblems <<= 1 {
		butterflies := subProblems >> 1 // Number of butterflies in one block.
		k++
		z := zetas[k]
		for block := 0; block < N; block += subProblems {
			for j := 0; j < butterflies; j++ {
				u := int32(p[block+j])
				v := int32(p[block+j+butterflies])
				t := int32(MontgomeryMul(int32(z), v))
				p[block+j] = int16(u + t)
				p[block+j+butterflies] = int16(u - t)
			}
		}
	}
}
