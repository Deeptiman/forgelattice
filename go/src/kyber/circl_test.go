package kyber

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestCIRCL_DecompressMessage(t *testing.T) {
	var m, m2 [32]byte
	var p Poly
	for i := 0; i < 1000; i++ {
		if n, err := rand.Read(m[:]); err != nil {
			t.Error(err)
		} else if n != len(m) {
			t.Fatal("short read from RNG")
		}

		p.DecompressMessage(m[:])
		p.CompressMessage(m2[:])
		if m != m2 {
			t.Fatal()
		}
	}
}

func TestCIRCL_CompressMessage(t *testing.T) {
	var p Poly
	var m [32]byte
	ok := true
	for i := 0; i < int(Q); i++ {
		p[0] = int16(i)
		p.CompressMessage(m[:])
		want := byte(0)
		if i >= 833 && i < 2497 {
			want = 1
		}
		if m[0] != want {
			ok = false
			t.Logf("%d %d %d", i, want, m[0])
		}
	}
	if !ok {
		t.Fatal()
	}
}

func TestCIRCL_EncryptThenDecrypt(t *testing.T) {
	var seed [32]byte
	var coin [32]byte

	for i := 0; i < 32; i++ {
		seed[i] = byte(i)
		coin[i] = byte(i)
	}

	for _, l := range []Level{Level512, Level768, Level1024} {
		t.Run(fmt.Sprintf("Encrypt-Decrypt=%s", l.String()), func(t *testing.T) {
			p := ParamsFor(l)
			for i := 0; i < 100; i++ {
				seed[0] = byte(i)
				p.GenerateKeyPair(seed[:])

				for j := 0; j < 100; j++ {
					var msg [32]byte
					ct := make([]byte, p.Cfg.CiphertextSize)

					_, _ = rand.Read(msg[:])
					_, _ = rand.Read(coin[:])

					p.Encrypt(ct[:], msg[:], coin[:])
					var pt [32]byte
					p.Decrypt(pt[:], ct[:])
					assert.Equal(t, hex.EncodeToString(msg[:]), hex.EncodeToString(pt[:]))
				}
			}
		})
	}
}

func TestCIRCL_KyberBarretTestVector(t *testing.T) {
	type testCases struct {
		x        int32
		expected int32
		expT     int32
	}
	tests := []testCases{
		{0, 0, 0},
		{1, 1, 0},
		{100, 100, 0},
		{2602, 2602, 0},
		{3328, 3328, 0},
		{3329, 0, 1},
		{3330, 1, 1},
		{65535, 2284, 19},
		{65536, 2285, 19},
		{-1, 3328, -1},
		{-3329, 0, -2},
		{-65536, 1044, -20},
	}
	for _, tc := range tests {
		m := (tc.x * BarrettK16Mu) >> 26
		assert.Equal(t, m, tc.expT)
		red := BarrettRedWith16bit(tc.x)
		assert.Equal(t, red, int16(tc.expected))
	}
}

func modQ32(x int32) int16 {
	y := x % int32(Q)
	if y < 0 {
		y += int32(Q)
	}
	return int16(y)
}

func TestCIRCL_KyberToMontgomeryFull(t *testing.T) {
	for x := -(1 << 15); x < 1<<15; x++ {
		y := ToMontgomeryWithKyber(int32(x))
		y1 := modQ32(int32(y))
		y2 := modQ32(int32(x * 2285))
		if y1 != y2 {
			t.Fatalf("%d:%d:%d", x, y1, y2)
		}
	}
}

func TestCIRCL_KyberMontgomeryEncodeDecode(t *testing.T) {
	for x := -(1 << 15); x <= (1 << 15); x++ {
		// 1) Encode: x --> xR mod Q
		enc := MontgomeryMul(int32(x), R2modQ)

		// 2) Decode: (xR) * R⁻¹ ≡ x mod Q
		dec := MontgomeryMul(int32(enc), 1)

		red := modQ32(int32(x))
		assert.Equal(t, dec, red)
	}
}
