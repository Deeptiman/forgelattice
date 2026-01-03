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
// 10. Encrypt random  32-bytes with PublicKey.
// 11. Decrypt the ciphertext with PrivateKey.

func (p *Params) GenerateKeyPair(seed []byte) (*PublicKey, *PrivateKey) {
	seedA, sigma := ExpandSeed(seed[:])

	copy(p.Pk.rho[:], seedA[:32])
	p.GeneratePublicMatrixA(&p.Pk.rho) // A

	for i := 0; i < p.Cfg.K; i++ {
		p.Sk.V[i].SampleNoise(sigma[:], uint8(i), p.Cfg.Eta1) // S
	}

	for i := 0; i < p.Cfg.K; i++ {
		p.Sk.V[i].NTT()
	}

	for i := 0; i < p.Cfg.K; i++ {
		p.Sk.V[i].Normalize()
	}

	eh := make(PolyVec, p.Cfg.K)
	for i := 0; i < p.Cfg.K; i++ {
		eh[i].SampleNoise(sigma[:], uint8(p.Cfg.K)+uint8(i), p.Cfg.Eta1) // e
	}

	for i := 0; i < p.Cfg.K; i++ {
		eh[i].NTT()
	}

	p.Pk.T = make(PolyVec, p.Cfg.K)
	for i := 0; i < p.Cfg.K; i++ {
		var t Poly
		publicMatrix := p.Pk.A[i]
		secretVector := p.Sk.V
		for j := 0; j < p.Cfg.K; j++ {
			t.MulWrapped(&publicMatrix[j], &secretVector[j])
		}
		p.Pk.T[i].Add(t)
		p.Pk.T[i].ToMont()
	}

	for i := 0; i < p.Cfg.K; i++ {
		p.Pk.T[i].Add(eh[i])
	}

	for i := 0; i < p.Cfg.K; i++ {
		p.Pk.T[i].Normalize()
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
	for x := 0; x < p.Cfg.K; x++ {
		for y := 0; y < p.Cfg.K; y++ {
			p.Pk.A[x][y].PolyUniform(rho, byte(y), byte(x))
		}
	}
}

func (p *Params) GenerateSecretVectorNoise(seed []byte, nonce uint8) {
	for i := 0; i < p.Cfg.K; i++ {
		switch p.Cfg.Eta1 {
		case 2:
			p.Sk.V[i].GenerateSecretVectorNoiseWithEta2(seed[:], nonce+uint8(i))
		case 3:
			p.Sk.V[i].GenerateSecretVectorNoiseWithEta3(seed[:], nonce+uint8(i))
		}
	}
}

func (p *Params) Transpose() {
	for i := 0; i < p.Cfg.K-1; i++ {
		for j := i + 1; j < p.Cfg.K; j++ {
			t := p.Pk.A[i][j]
			p.Pk.A[i][j] = p.Pk.A[j][i]
			p.Pk.A[j][i] = t
		}
	}
}
