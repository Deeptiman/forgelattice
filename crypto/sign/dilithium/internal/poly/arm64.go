//go:build arm64 && !purego
// +build arm64,!purego

package poly

//go:noescape
func polyAddARM64(p, a, b *Poly)

//go:noescape
func polySubARM64(p, a, b *Poly)

//go:noescape
func polyMulBy2toDARM64(p, q *Poly)

//go:noescape
func polyPackLe16ARM64(p *Poly, buf *byte)
