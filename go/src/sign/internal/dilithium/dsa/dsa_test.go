package dsa

import (
	"encoding/binary"
	"fmt"
	"github.com/Deeptiman/forgekey/go/src/sign/internal/dilithium/common"
	"testing"
)

func TestPublicFromPrivate(t *testing.T) {
	for _, l := range []Level{Level2, Level3, Level5} {
		t.Run(fmt.Sprintf("%s", l.String()), func(t *testing.T) {
			for i := 0; i < 100; i++ {
				d := NewDilithium(l)
				var seed [common.SeedSize]byte
				binary.LittleEndian.PutUint64(seed[:], uint64(i))
				pk, sk := d.GenerateKeyPair(seed)
				pk2 := sk.GetPublicKey(d.K, d.L)
				if !pk.Equal(d.K, pk2) {
					t.Fatal()
				}
			}
		})
	}
}
