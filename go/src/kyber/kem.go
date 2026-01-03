package kyber

func (p *Params) Encrypt(ct, pt, seed []byte) {
	rh := make(PolyVec, p.Cfg.K)
	e1 := make(PolyVec, p.Cfg.K)
	var e2 Poly

	// 1. Sample noise (r, e1, e2)
	for i := 0; i < p.Cfg.K; i++ {
		rh[i].SampleNoise(seed, uint8(i), p.Cfg.Eta1)
	}

	for i := 0; i < p.Cfg.K; i++ {
		rh[i].NTT()
	}

	for i := 0; i < p.Cfg.K; i++ {
		rh[i].Normalize()
	}

	for i := 0; i < p.Cfg.K; i++ {
		e1[i].SampleNoise(seed, uint8(p.Cfg.K)+uint8(i), p.Cfg.Eta2)
	}
	e2.SampleNoise(seed, uint8(2*p.Cfg.K), p.Cfg.Eta2)

	// 2. u = A^T . r + e1
	u := make(PolyVec, p.Cfg.K)
	for i := 0; i < p.Cfg.K; i++ {
		var tmp Poly
		for j := 0; j < p.Cfg.K; j++ {
			tmp.MulWrapped(&p.Pk.A[i][j], &rh[j])
		}
		u[i].Add(tmp)
	}

	for i := 0; i < p.Cfg.K; i++ {
		u[i].Normalize()
	}

	for i := 0; i < p.Cfg.K; i++ {
		u[i].InvNTT()
	}

	for i := 0; i < p.Cfg.K; i++ {
		u[i].Add(e1[i])
	}

	// 3. v = t . r + e2 + m
	var v, m, tmp Poly
	for i := 0; i < p.Cfg.K; i++ {
		tmp.MulWrapped(&p.Pk.T[i], &rh[i])
	}
	v.Add(tmp)
	v.Normalize()
	v.InvNTT()

	m.DecompressMessage(pt)
	v.Add(m)
	v.Add(e2)

	for i := 0; i < p.Cfg.K; i++ {
		u[i].Normalize()
	}
	v.Normalize()

	// 4. Compress
	size := compressedPolySize(p.Cfg.Du)
	for i := 0; i < p.Cfg.K; i++ {
		u[i].Compress(ct[size*i:], p.Cfg.Du)
	}
	v.Compress(ct[p.Cfg.K*size:], p.Cfg.Dv)
}

func (p *Params) Decrypt(pt []byte, ct []byte) {
	var u PolyVec
	var v, m Poly

	size := compressedPolySize(p.Cfg.Du)
	u = make(PolyVec, p.Cfg.K)
	for i := 0; i < p.Cfg.K; i++ {
		u[i].Decompress(ct[size*i:], p.Cfg.Du)
	}
	v.Decompress(ct[p.Cfg.K*size:], p.Cfg.Dv)

	for i := 0; i < p.Cfg.K; i++ {
		u[i].NTT()
	}

	var tmp Poly
	for i := 0; i < p.Cfg.K; i++ {
		tmp.MulWrapped(&p.Sk.V[i], &u[i])
	}
	m.Add(tmp)
	m.Normalize()
	m.InvNTT()
	m.Sub(v)
	m.Normalize()
	m.CompressMessage(pt)
}
