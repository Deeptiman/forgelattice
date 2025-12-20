package kyber

func NTT(coeffs []int16, zetas [128]int16) []int16 {
	coeffsInput := make([]int16, N)
	copy(coeffsInput, coeffs)

	k := 0
	for subProblems := 2; subProblems <= N; subProblems <<= 1 {
		butterflies := subProblems >> 1 // Number of butterflies in one block.
		for block := 0; block < N; block += subProblems {
			for j := 0; j < butterflies; j++ {
				z := zetas[k]
				k++

				u := int32(coeffsInput[block+j])
				v := int32(coeffsInput[block+j+butterflies])
				t := int32(MontgomeryMul(int32(z), v))
				coeffsInput[block+j] = int16(u + t)
				coeffsInput[block+j+butterflies] = int16(u - t)
			}
		}
	}
	return coeffsInput
}
