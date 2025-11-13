package sampler

import (
	"math"
	"math/rand"
)

// Ziggurat Method for Random Number Generation (The Ziggurat Method for Generating Random Variables) (Marsaglia & Tsang, 2000)
// http://www.jstatsoft.org/v05/i08/paper

const (
	// m1 is a scaling factor that used to convert floating-point layer boundaries into integer thresholds
	// for efficient sampling.
	// 2^31 scale factor for each layer
	m1 = 2147483648.0
	// vn represents area of each Ziggurat layer for the normal distribution. Ziggurat method divides the area
	// of each layer under f(x) = (e**(-x**2/2)) into 128 or 255 layers, each with equal area.
	//
	// Total area for x >= 0 is:
	//
	//	∫(e**(-x**2/2))dx = sqrt(2π/2) = 1.25331413732
	//
	//	For 128 layers, the area per layer is:
	//
	//	 sqrt(2π/2.128) = 0.009791516697
	//
	vn = 9.91256303526217e-3
)

// dn is the rightmost boundary of the Ziggurat layers defining the x-coordinate (excluding the tail area)
// where the Gaussian PDF is evaluated for the last layer(x127).
//
// dn is chosen such that the area beyond the tail is small and the remaining area is divided into 128 layers
// of area (vn).
var dn = 3.442619855899 // erfc to keep a symmetric coordinate from the origin

// ZigguratTable stores the precomputed table for sample generation using Ziggurat method.
type ZigguratTable struct {
	// kn stores the indices as integer thresholds used for layer selection. It's useful for fast-path check
	// to determine if a sample (x=j.wn[i]) within the curve.
	kn [128]uint32
	// wn stores the width of the rectangles under a curve. It ensures efficient sampling by mapping random
	// integers to the correct range within each layer.
	wn [128]float32
	// fn stores the Probability Density Function (PDF) values at specific point (xi) of the layer boundaries.
	fn [128]float32
}

// GenerateComputationTable computes the Ziggurat table to be used for sample generation.
func (s *Sampler) GenerateComputationTable() *ZigguratTable {
	// Table for Normal distribution

	// compute the scaling factor
	q := vn / math.Exp(-0.5*dn*dn)

	t := new(ZigguratTable)

	// integer threshold of layer-0 & layer-1
	t.kn[0] = uint32((dn / q) * m1)
	t.kn[1] = 0

	// width of layer-0 & layer-127
	t.wn[0] = float32(q / m1)
	t.wn[127] = float32(dn / m1)

	// PDF value at x=0 (e^0=1)
	t.fn[0] = 1.0
	// PDF value at x=dn (the tail)
	t.fn[127] = float32(math.Exp(-0.5 * dn * dn))

	tn := dn // tn as previous boundary
	for i := 126; i >= 1; i-- {
		// compute next boundary
		dn = math.Sqrt(-2.0 * math.Log(vn/dn+math.Exp(-0.5*dn*dn)))
		t.kn[i+1] = uint32((dn / tn) * m1)
		t.fn[i] = float32(math.Exp(-0.5 * dn * dn))
		t.wn[i] = float32(dn / m1)
		tn = dn
	}
	return t
}

// NormalSampling generates sample distributions for 128 layers.
func (z *ZigguratTable) NormalSampling(prng *rand.Rand) (float64, uint64) {
	const rn = 3.442619855899 // right most boundary for tail sampling
	for {
		juint32 := uint32(prng.Int63() >> 31)
		sign := uint64(juint32 >> 31)
		j := int32(juint32 & 0x7fffffff)
		i := j & 0x7F
		x := float64(j) * float64(z.wn[i])
		if uint32(j) < z.kn[i] {
			return x, sign
		}
		if i == 0 { // infinite loop for the tail sampling.
			for {
				x = -math.Log(prng.Float64()) * (1.0 / rn)
				y := -math.Log(prng.Float64())
				if y+y >= x*x {
					return x + rn, sign
				}
			}
		}
		// Check if sampling is done under the PDF curve
		if z.fn[i]+float32(prng.Float64())*(z.fn[i-1]-z.fn[i]) < float32(math.Exp(-0.5*x*x)) {
			return x, sign
		}
	}
}
