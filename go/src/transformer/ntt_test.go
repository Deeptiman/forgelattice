package transformer

import (
	"github.com/Deeptiman/forgekey/go/src/prime"
	"github.com/stretchr/testify/assert"
	"math/big"
	"testing"
)

func TestNTT(t *testing.T) {

}

func TestFindPrimitiveRoots(t *testing.T) {
	q := int64(8380417)
	qBig := new(big.Int).Sub(big.NewInt(q), big.NewInt(1))
	n := &NTTTable{Q: q, Order: 512} // Dilithium
	factors := prime.GetPrimeFactor(qBig, prime.PollardRho)
	assert.Equal(t, n.FindPrimitiveRoots(factors), int64(1753))

	q = int64(3329)
	qBig = new(big.Int).Sub(big.NewInt(q), big.NewInt(1))
	n = &NTTTable{Q: q, Order: 256} // Kyber
	factors = prime.GetPrimeFactor(qBig, prime.PollardRho)
	assert.Equal(t, n.FindPrimitiveRoots(factors), int64(17))
}
