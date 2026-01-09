package kem

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/Deeptiman/forgekey/go/src/kem/internal/kyber/common"
	"github.com/Deeptiman/forgekey/go/src/kem/internal/kyber/cpapke"
	"github.com/Deeptiman/forgekey/go/src/kem/internal/kyber/poly"
	"github.com/Deeptiman/forgekey/go/src/kem/mlkem/fips203"
	"github.com/Deeptiman/forgekey/go/src/kem/testdata"
	"github.com/stretchr/testify/assert"
	"io"
	"os"
	"testing"
)

func TestCIRCL_DecompressMessage(t *testing.T) {
	var m, m2 [32]byte
	var p poly.Poly
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
	var p poly.Poly
	var m [32]byte
	ok := true
	for i := 0; i < int(common.Q); i++ {
		p = poly.WithCoeffs([common.N]int16{int16(i)})
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

	for _, l := range []cpapke.Level{cpapke.Level512, cpapke.Level768, cpapke.Level1024} {
		t.Run(fmt.Sprintf("Encrypt-Decrypt=%s", l.String()), func(t *testing.T) {
			for i := 0; i < 100; i++ {
				seed[0] = byte(i)
				p := cpapke.WithKyberConfigs(l)
				k := p.GenerateKeyPair(seed[:])

				for j := 0; j < 100; j++ {
					var msg [32]byte
					ct := make([]byte, p.CiphertextSize)

					_, _ = rand.Read(msg[:])
					_, _ = rand.Read(coin[:])

					k.Encrypt(ct[:], msg[:], coin[:])
					var pt [32]byte
					k.Decrypt(pt[:], ct[:])
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
		m := (tc.x * common.BarrettK16Mu) >> 26
		assert.Equal(t, m, tc.expT)
		red := poly.BarrettRedWith16bit(tc.x)
		assert.Equal(t, red, int16(tc.expected))
	}
}

func modQ32(x int32) int16 {
	y := x % int32(common.Q)
	if y < 0 {
		y += int32(common.Q)
	}
	return int16(y)
}

func TestCIRCL_KyberToMontgomeryFull(t *testing.T) {
	for x := -(1 << 15); x < 1<<15; x++ {
		y := poly.ToMontgomery(int32(x))
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
		enc := poly.MontgomeryMul(int32(x), common.R2modQ)

		// 2) Decode: (xR) * R⁻¹ ≡ x mod Q
		dec := poly.MontgomeryMul(int32(enc), 1)

		red := modQ32(int32(x))
		assert.Equal(t, dec, red)
	}
}

func openTestData(t *testing.T, fileName string) []byte {
	file, err := os.Open("./testdata/" + fileName)
	assert.Nil(t, err)
	defer file.Close()

	jsonData, err := io.ReadAll(file)
	assert.Nil(t, err)
	return jsonData
}

func TestCIRCL_KeyGenerationFIPS203(t *testing.T) {
	var keyGenPayload testdata.KeyGenerationPayload
	err := json.Unmarshal(openTestData(t, "ML-KEM-keyGen-FIPS203/prompt.json"), &keyGenPayload)
	assert.Nil(t, err)

	var expectedKeyGenResult testdata.ExpectedKeyGenResult
	err = json.Unmarshal(openTestData(t, "ML-KEM-keyGen-FIPS203/expectedResults.json"), &expectedKeyGenResult)
	assert.Nil(t, err)

	for i, testGroup := range keyGenPayload.TestGroups {
		k := &KEM{protocol: fips203.New(cpapke.ToLevel(testGroup.ParameterSet))}
		for j, test := range testGroup.Tests {
			z := mustHex(test.Z)
			d := mustHex(test.D)
			var seed [64]byte
			copy(seed[:], d)
			copy(seed[32:], z)

			pk, sk := k.GenerateKeyPair(seed[:])
			Ek := mustHex(expectedKeyGenResult.TestGroups[i].Tests[j].Ek)
			Dk := mustHex(expectedKeyGenResult.TestGroups[i].Tests[j].Dk)

			ek := k.protocol.UnPackPublicKey(Ek)
			dk := k.protocol.UnPackPrivateKey(Dk)

			assert.Equal(t, ek, pk)
			assert.Equal(t, dk, sk)
		}
	}
}

func TestCIRCL_EncapsulateAndDecapsulate(t *testing.T) {
	var encapsDecaps testdata.EncapsDecapsPayload
	err := json.Unmarshal(openTestData(t, "ML-KEM-encapDecap-FIPS203/prompt.json"), &encapsDecaps)
	assert.Nil(t, err)

	var expectedEncapsDecaps testdata.EncapsDecapsExpectedResults
	err = json.Unmarshal(openTestData(t, "ML-KEM-encapDecap-FIPS203/expectedResults.json"), &expectedEncapsDecaps)
	assert.Nil(t, err)
	for i, testGroup := range encapsDecaps.TestGroups {
		for j, test := range testGroup.Tests {
			if testGroup.Function == "encapsulation" {
				t.Run(fmt.Sprintf("%s:%s:%d:%d", testGroup.Function, testGroup.ParameterSet, testGroup.TgID, test.TcID), func(t *testing.T) {
					k := &KEM{protocol: fips203.New(cpapke.ToLevel(testGroup.ParameterSet))}
					ek := mustHex(test.Ek)
					m := mustHex(test.M)
					ct1 := mustHex(expectedEncapsDecaps.TestGroups[i].Tests[j].C)
					ss1 := mustHex(expectedEncapsDecaps.TestGroups[i].Tests[j].K)
					ek1 := k.protocol.UnPackPublicKey(ek)
					ct, ss := k.Encapsulate(ek1, m)
					assert.True(t, bytes.Equal(ct1, ct))
					assert.True(t, bytes.Equal(ss1, ss))
				})
			}
			if testGroup.Function == "decapsulation" {
				t.Run(fmt.Sprintf("%s:%s:%d:%d", testGroup.Function, testGroup.ParameterSet, testGroup.TgID, test.TcID), func(t *testing.T) {
					k := &KEM{protocol: fips203.New(cpapke.ToLevel(testGroup.ParameterSet))}
					c := mustHex(test.C)
					dk := mustHex(testGroup.Dk)
					k1 := mustHex(expectedEncapsDecaps.TestGroups[i].Tests[j].K)
					dk1 := k.protocol.UnPackPrivateKey(dk)
					ss := k.Decapsulate(dk1, c)
					assert.True(t, bytes.Equal(ss[:], k1[:]))
				})
			}
		}
	}
}
