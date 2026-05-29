package dsa

import (
	"encoding/binary"
	"fmt"
	"github.com/Deeptiman/forgelattice/crypto/dsa/internal/common"
	"github.com/Deeptiman/forgelattice/crypto/dsa/internal/sign"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestSignThenVerifyAndPkSkPacking(t *testing.T) {
	for _, l := range []Level{sign.Level2, sign.Level3, sign.Level5} {
		t.Run(fmt.Sprintf("%s", l.String()), func(t *testing.T) {
			for i := 0; i < 10; i++ {
				var seed [common.SeedSize]byte
				d := WithFIPS204(l)
				binary.LittleEndian.PutUint64(seed[:], uint64(i))
				pk, sk := d.GenerateKeyPair(seed)
				for j := 0; j < 10; j++ {
					t.Run(fmt.Sprintf("signAndverify=%s-%d-%d", l.String(), i, j), func(t *testing.T) {
						skBytes := d.MarshalPrivateKey(sk)
						var msgBytes [8]byte
						binary.LittleEndian.PutUint64(msgBytes[:], uint64(i+j))
						var rnd [32]byte // deterministic randomness.
						sigBytes := d.Sign(skBytes, msgBytes[:], rnd)
						pkBytes := d.MarshalPublicKey(pk)
						assert.NotNil(t, pkBytes)
						assert.True(t, d.Verify(pkBytes, sigBytes, msgBytes[:]))
					})
				}
			}
		})
	}
}
