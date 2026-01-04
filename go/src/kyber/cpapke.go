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

	for i := 0; i < p.K; i++ {
		p.Sk.V[i].SampleNoise(sigma[:], uint8(i), p.Eta1) // S
	}

	for i := 0; i < p.K; i++ {
		p.Sk.V[i].NTT()
	}

	for i := 0; i < p.K; i++ {
		p.Sk.V[i].Normalize()
	}

	eh := make(PolyVec, p.K)
	for i := 0; i < p.K; i++ {
		eh[i].SampleNoise(sigma[:], uint8(p.K)+uint8(i), p.Eta1) // e
	}

	for i := 0; i < p.K; i++ {
		eh[i].NTT()
	}

	p.Pk.T = make(PolyVec, p.K)
	for i := 0; i < p.K; i++ {
		var t Poly
		publicMatrix := p.Pk.A[i]
		secretVector := p.Sk.V
		for j := 0; j < p.K; j++ {
			t.MulWrapped(&publicMatrix[j], &secretVector[j])
		}
		p.Pk.T[i].Add(t)
		p.Pk.T[i].ToMont()
	}

	for i := 0; i < p.K; i++ {
		p.Pk.T[i].Add(eh[i])
	}

	for i := 0; i < p.K; i++ {
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
	for x := 0; x < p.K; x++ {
		for y := 0; y < p.K; y++ {
			p.Pk.A[x][y].PolyUniform(rho, byte(y), byte(x))
		}
	}
}

func (p *Params) GenerateSecretVectorNoise(seed []byte, nonce uint8) {
	for i := 0; i < p.K; i++ {
		switch p.Eta1 {
		case 2:
			p.Sk.V[i].GenerateSecretVectorNoiseWithEta2(seed[:], nonce+uint8(i))
		case 3:
			p.Sk.V[i].GenerateSecretVectorNoiseWithEta3(seed[:], nonce+uint8(i))
		}
	}
}

func (p *Params) Encrypt(ct, pt, seed []byte) {
	rh := make(PolyVec, p.K)
	e1 := make(PolyVec, p.K)
	var e2 Poly

	// 1. Sample noise (r, e1, e2)
	for i := 0; i < p.K; i++ {
		rh[i].SampleNoise(seed, uint8(i), p.Eta1)
	}

	for i := 0; i < p.K; i++ {
		rh[i].NTT()
	}

	for i := 0; i < p.K; i++ {
		rh[i].Normalize()
	}

	for i := 0; i < p.K; i++ {
		e1[i].SampleNoise(seed, uint8(p.K)+uint8(i), p.Eta2)
	}
	e2.SampleNoise(seed, uint8(2*p.K), p.Eta2)

	// 2. u = A^T . r + e1
	u := make(PolyVec, p.K)
	for i := 0; i < p.K; i++ {
		var tmp Poly
		for j := 0; j < p.K; j++ {
			tmp.MulWrapped(&p.Pk.A[i][j], &rh[j])
		}
		u[i].Add(tmp)
	}

	for i := 0; i < p.K; i++ {
		u[i].Normalize()
	}

	for i := 0; i < p.K; i++ {
		u[i].InvNTT()
	}

	for i := 0; i < p.K; i++ {
		u[i].Add(e1[i])
	}

	// 3. v = t . r + e2 + m
	var v, m, tmp Poly
	for i := 0; i < p.K; i++ {
		tmp.MulWrapped(&p.Pk.T[i], &rh[i])
	}
	v.Add(tmp)
	v.Normalize()
	v.InvNTT()

	m.DecompressMessage(pt)
	v.Add(m)
	v.Add(e2)

	for i := 0; i < p.K; i++ {
		u[i].Normalize()
	}
	v.Normalize()

	// 4. Compress
	size := compressedPolySize(p.Du)
	for i := 0; i < p.K; i++ {
		u[i].Compress(ct[size*i:], p.Du)
	}
	v.Compress(ct[p.K*size:], p.Dv)
}

func (p *Params) Decrypt(pt []byte, ct []byte) {
	var u PolyVec
	var v, m Poly

	size := compressedPolySize(p.Du)
	u = make(PolyVec, p.K)
	for i := 0; i < p.K; i++ {
		u[i].Decompress(ct[size*i:], p.Du)
	}
	v.Decompress(ct[p.K*size:], p.Dv)

	for i := 0; i < p.K; i++ {
		u[i].NTT()
	}

	var tmp Poly
	for i := 0; i < p.K; i++ {
		tmp.MulWrapped(&p.Sk.V[i], &u[i])
	}
	m.Add(tmp)
	m.Normalize()
	m.InvNTT()
	m.Sub(v)
	m.Normalize()
	m.CompressMessage(pt)
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
