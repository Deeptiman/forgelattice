package kyber

// Kyber key-generation steps [PublicKey, PrivateKey]
// 1. Generate 32-bytes random seed
// 2. Expand seed with SHAKE256
// 3. Split the seed into seedA and seedS
// 4. Deterministically generate public matrix A from seedA
// 5. Sample secret vector s using CBD (Centered Binomial Distribution)
// 6. Sample noise vector e using CBD (Centered Binomial Distribution)
// 7. Compute [A * s + e (mod Q)]
// 8. Output public key (seedA, t)
// 9. Output secret key s

func (p *Params) GenerateKeyPair() (*PublicKey, *PrivateKey) {
	seed, _ := GenerateRandomBytes(nil)
	seedA, sigma := ExpandSeed(seed[:])

	copy(p.Pk.rho[:], seedA[:])

	p.GeneratePublicMatrixA(&p.Pk.rho) // A

	p.GenerateSecretVectorNoise(sigma[:], 0) // S
	p.SecretVectorToNTT()

	p.GenerateLWENoise(seed[:], uint8(p.K)) // e
	p.LWEToNTT()

	p.MulMatrixAWithSecretVector()

	for i := 0; i < p.K; i++ {
		p.Pk.T[i].Add(p.Lwe[i])
	}
	p.Transpose()
	return &p.Pk, &p.Sk
}

func (p *Params) GeneratePublicMatrixA(rho *[32]byte) {
	// 1. Gather 32-bytes random numbers (rho).
	// 2. Shake it with 128-bit for each row & column and rho bytes.
	// 3. Apply rejection sampler for each iteration to collect 12-bits of buffer.
	// 4. Add it to the polynomial coefficients.
	// 5. Complete the loop to generate KxK matrix uniform within [0 ... Q)
	for x := 0; x < p.K; x++ {
		for y := 0; y < p.K; y++ {
			p.Pk.A[x][y].PolyUniform(rho, byte(y), byte(x))
		}
	}
}

func (p *Params) GenerateSecretVectorNoise(seed []byte, nonce uint8) {
	for i := 0; i < p.K; i++ {
		switch p.Eta {
		case 2:
			p.Sk.V[i].GenerateSecretVectorNoiseWithEta2(seed[:], nonce+uint8(i+0x1f))
		case 3:
			p.Sk.V[i].GenerateSecretVectorNoiseWithEta3(seed[:], nonce+uint8(i+0x1f))
		}
	}
}

func (p *Params) GenerateLWENoise(seed []byte, nonce uint8) {
	p.Lwe = make(PolyVec, p.K)
	for i := 0; i < p.K; i++ {
		switch p.Eta {
		case 2:
			p.Lwe[i].GenerateSecretVectorNoiseWithEta2(seed[:], nonce+uint8(i+0x1f))
		case 3:
			p.Lwe[i].GenerateSecretVectorNoiseWithEta3(seed[:], nonce+uint8(i+0x1f))
		}
	}
}

func (p *Params) LWEToNTT() {
	for i := 0; i < p.K; i++ {
		p.Lwe[i].NTT(p.Zetas)
	}
}

func (p *Params) SecretVectorToNTT() {
	for i := 0; i < p.K; i++ {
		p.Sk.V[i].NTT(p.Zetas)
		p.Sk.V[i].Normalize()
	}
}

func (p *Params) MulMatrixAWithSecretVector() {
	p.Pk.T = make(PolyVec, p.K)
	for i := 0; i < p.K; i++ {
		p.Pk.T[i].Zero()
		for j := 0; j < p.K; j++ {
			p.Pk.T[i].MulWrapped(&p.Pk.A[i][j], &p.Sk.V[i], p.Zetas)
		}
		p.Pk.T[i].ToMont()
	}
}

func (p *Params) Transpose() {
	for i := 0; i < p.K-1; i++ {
		for j := i + 1; j < p.K; j++ {
			t := p.Pk.A[i][j]
			p.Pk.A[i][j] = p.Pk.A[j][i]
			p.Pk.A[j][i] = t
		}
	}
}
