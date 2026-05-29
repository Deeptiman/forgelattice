package common

import (
	cryptRand "crypto/rand"
	"github.com/Deeptiman/forgelattice/crypto/sha3"
	"io"
)

func GenerateRandomBytes(rand io.Reader) ([SeedSize]byte, error) {
	var seed [SeedSize]byte
	if rand == nil {
		rand = cryptRand.Reader
	}
	_, err := io.ReadFull(rand, seed[:])
	if err != nil {
		return [SeedSize]byte{}, err
	}
	return seed, nil
}

func ExpandSeed(seed []byte) (seedA [SeedSize]byte, seedS [SeedSize]byte) {
	var buf [64]byte
	s := sha3.New512()
	_, _ = s.Write(seed)
	s.Read(buf[:])
	copy(seedA[:], buf[:SeedSize])
	copy(seedS[:], buf[SeedSize:])
	return
}
