package sha3

import (
	"encoding/hex"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestStateHash_WithSHAKE256(t *testing.T) {
	k := []byte("this is a secret key; you should generate a strong random key that's at least 32 bytes long")
	buf := []byte("and this is some data to authenticate")

	s := NewShake256()
	out := make([]byte, 32)
	s.Write(k)
	s.Write(buf)
	s.Read(out)
	assert.Equal(t, "78de2974bd2711d5549ffd32b753ef0f5fa80a0db2556db60f0987eb8a9218ff", hex.EncodeToString(out))
	// Output: 78de2974bd2711d5549ffd32b753ef0f5fa80a0db2556db60f0987eb8a9218ff
}

func TestStateHash_WithSHAKE128(t *testing.T) {
	k := []byte("this is a secret key; you should generate a strong random key that's at least 32 bytes long")
	buf := []byte("and this is some data to authenticate")

	s := NewShake128()
	out := make([]byte, 32)
	s.Write(k)
	s.Write(buf)
	s.Read(out)
	assert.Equal(t, "8cc1e412dac16d2497d10d8293351f8de537aaea0984b9f5bd0c3faaaf7d9fe5", hex.EncodeToString(out))
}
