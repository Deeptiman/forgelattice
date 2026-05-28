package poly

func (v Vec) Add(p Vec) Vec {
	dimensions := len(v)
	for i := 0; i < dimensions; i++ {
		v[i].Add(p[i])
	}
	return v
}

func (v Vec) Sub(p Vec) Vec {
	dimensions := len(v)
	for i := 0; i < dimensions; i++ {
		v[i].Sub(p[i])
	}
	return v
}

func (v Vec) NTT() {
	for i := 0; i < len(v); i++ {
		v[i].NTT()
	}
}

func (v Vec) InvNTT() {
	for i := 0; i < len(v); i++ {
		v[i].InvNTT()
	}
}

func (v Vec) Reduce() {
	for i := 0; i < len(v); i++ {
		v[i].Reduce()
	}
}

func (v Vec) SampleNoise(seed []byte, K int, eta int) {
	for i := 0; i < len(v); i++ {
		v[i].SampleNoise(seed, uint8(K)+uint8(i), eta)
	}
}
