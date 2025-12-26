package kyber

import (
	cryptRand "crypto/rand"
	"github.com/Deeptiman/forgekey/go/src/sha3"
	"io"
)

func GenerateRandomBytes(rand io.Reader) ([32]byte, error) {
	var seed [32]byte
	if rand == nil {
		rand = cryptRand.Reader
	}
	_, err := io.ReadFull(rand, seed[:])
	if err != nil {
		return [32]byte{}, err
	}
	return seed, nil
}

func ExpandSeed(seed []byte) (seedA [32]byte, seedS [32]byte) {
	var buf [64]byte
	s := sha3.New512()
	_, _ = s.Write(seed)
	s.Read(buf[:])
	copy(seedA[:], buf[:32])
	copy(seedS[:], buf[32:])
	return
}
