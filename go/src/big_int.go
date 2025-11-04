package src

import (
	"math/big"
	"math/rand"
)

type BigInt struct {
	n *big.Int
}

func NewBigInt() *BigInt {
	return &BigInt{new(big.Int)}
}

func (n *BigInt) Mul(a, b *big.Int) *big.Int {
	return n.n.Mul(a, b)
}

func (n *BigInt) Div(a, b *big.Int) *big.Int {
	return n.n.Div(a, b)
}

func (n *BigInt) Add(a, b *big.Int) *big.Int {
	return n.n.Add(a, b)
}

func (n *BigInt) Sub(a, b *big.Int) *big.Int {
	return n.n.Sub(a, b)
}

func (n *BigInt) Neg(a *big.Int) *big.Int {
	return n.n.Neg(a)
}

func (n *BigInt) Mod(a, b *big.Int) *big.Int {
	return n.n.Mod(a, b)
}

func (n *BigInt) Set(a *big.Int) *big.Int {
	return n.n.Set(a)
}

func (n *BigInt) SetUint64(x uint64) *big.Int {
	return n.n.SetUint64(x)
}

func (n *BigInt) GCD(a, b *big.Int) *big.Int {
	return n.n.GCD(nil, nil, a, b)
}

func (n *BigInt) Rand(r *rand.Rand, a *big.Int) *big.Int {
	return n.Rand(r, a)
}
