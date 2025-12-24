package sha3

import (
	"fmt"
	"testing"
)

func TestState_Hash(t *testing.T) {
	k := []byte("this is a secret key; you should generate a strong random key that's at least 32 bytes long")
	buf := []byte("and this is some data to authenticate")

	s := &State{rate: 136, buffOffSets: 0, dsBytes: 0x01}
	out := make([]byte, 32)
	s.Hash(k)
	s.Hash(buf)
	s.Read(out)
	fmt.Printf("%x\n", out)
}
