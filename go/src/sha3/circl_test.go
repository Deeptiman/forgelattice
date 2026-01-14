// This test file is adapted from the CIRCL (Cloudflare) SHA-3 / Keccak test vectors and is
// used to standardize and validate this SHA-3 implementation against known-good reference outputs.
//
// Source:
// - https://github.com/cloudflare/circl/blob/main/internal/sha3/sha3_test.go
//
// The Keccak Known Answer Tests (KATs) are stored in compressed form under testdata/keccakKats.json.deflate.
package sha3

import (
	"compress/flate"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/Deeptiman/forgekey/go/src/sha3/keccak"
	"github.com/stretchr/testify/assert"
	"math/rand"
	"os"
	"strings"
	"testing"
)

const (
	katFilename = "testdata/keccakKats.json.deflate"
)

func TestNew512(t *testing.T) {
	var seed [32]byte
	for i := 0; i < 32; i++ {
		seed[i] = byte(i)
	}
	seed[0] = byte(5)
	var expSeed [64]byte
	h1 := New512()
	_, _ = h1.Write(seed[:])
	h1.Read(expSeed[:])
	assert.Equal(t, expSeed, [64]byte{52, 193, 209, 219, 73, 20, 126, 176, 63, 152, 104, 52, 208, 83, 48, 171, 41, 132, 137, 178, 192, 82, 242, 136, 246, 85, 3, 176, 23, 127, 78, 32, 120, 230, 199, 126, 165, 190, 21, 142, 188, 75, 11, 89, 227, 180, 72, 195, 182, 186, 21, 241, 110, 38, 12, 153, 9, 57, 128, 114, 154, 34, 60, 206})
}

func TestStateHash_WithSHAKE256(t *testing.T) {
	k := []byte("this is a secret key; you should generate a strong random key that's at least 32 bytes long")
	buf := []byte("and this is some data to authenticate")

	s := NewShake256()
	out := make([]byte, 32)
	s.Write(k)
	s.Write(buf)
	s.Read(out)
	assert.Equal(t, "78de2974bd2711d5549ffd32b753ef0f5fa80a0db2556db60f0987eb8a9218ff", hex.EncodeToString(out))
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

func TestShakeSum256(t *testing.T) {
	buf := []byte("some data to hash")
	// A hash needs to be 64 bytes long to have 256-bit collision resistance.
	h := make([]byte, 64)
	// Compute a 64-byte hash of buf and put it in h.
	ShakeSum256(h, buf)
	assert.Equal(t, "0f65fe41fc353e52c55667bb9e2b27bfcc8476f2c413e9437d272ee3194a4e3146d05ec04a25d16b8f577c19b82d16b1424c3e022e783d2b4da98de3658d363d", hex.EncodeToString(h))
}

func TestStateHashRhoOffsets(t *testing.T) {
	assert.Equal(t, keccak.RhoOffsets(), [25]int{
		0, 1, 62, 28, 27,
		36, 44, 6, 55, 20,
		3, 10, 43, 25, 39,
		41, 45, 15, 21, 8,
		18, 2, 61, 56, 14,
	})
}

// testDigests contains functions returning hash.Hash instances
// with output-length equal to the KAT length for SHA-3, Keccak
// and SHAKE instances.
var testDigests = map[string]func() State{
	"SHA3-224": New224,
	"SHA3-256": New256,
	"SHA3-384": New384,
	"SHA3-512": New512,
}

// structs used to marshal JSON test-cases.
type KeccakKats struct {
	Kats map[string][]struct {
		Digest  string `json:"digest"`
		Length  int64  `json:"length"`
		Message string `json:"message"`

		// Defined only for cSHAKE
		N string `json:"N"`
		S string `json:"S"`
	}
}

// TestKeccakKats tests the SHA-3 and Shake implementations against all the
// ShortMsgKATs from https://github.com/gvanas/KeccakCodePackage
// (The testvectors are stored in keccakKats.json.deflate due to their length.)
func TestKeccakKats(t *testing.T) {
	// Read the KATs.
	deflated, err := os.Open(katFilename)
	if err != nil {
		t.Errorf("error opening %s: %s", katFilename, err)
	}
	file := flate.NewReader(deflated)
	dec := json.NewDecoder(file)
	var katSet KeccakKats
	err = dec.Decode(&katSet)
	if err != nil {
		t.Errorf("error decoding KATs: %s", err)
	}

	for algo, function := range testDigests {
		for _, kat := range katSet.Kats[algo] {
			d := function()
			in, err := hex.DecodeString(kat.Message)
			if err != nil {
				t.Errorf("error decoding KAT: %s", err)
			}
			_, _ = d.Write(in[:kat.Length/8])
			got := strings.ToUpper(hex.EncodeToString(d.Sum(nil)))
			if got != kat.Digest {
				t.Errorf("function=%s, length=%d\nmessage:\n %s\ngot:\n  %s\nwanted:\n %s",
					algo, kat.Length, kat.Message, got, kat.Digest)
				t.Logf("wanted %+v", kat)
				t.FailNow()
			}
			continue
		}
	}
}

// sequentialBytes produces a buffer of size consecutive bytes 0x00, 0x01, ..., used for testing.
//
// The alignment of each slice is intentionally randomized to detect alignment
// issues in the implementation. See https://golang.org/issue/37644.
// Ideally, the compiler should fuzz the alignment itself.
// (See https://golang.org/issue/35128.)
func sequentialBytes(size int) []byte {
	alignmentOffset := rand.Intn(8) // nolint:gosec
	result := make([]byte, size+alignmentOffset)[alignmentOffset:]
	for i := range result {
		result[i] = byte(i)
	}
	return result
}

// benchmarkShake is specialized to the Shake instances, which don't
// require a copy on reading output.
func benchmarkShake(b *testing.B, h State, size, num int) {
	b.StopTimer()
	h.Reset()
	data := sequentialBytes(size)
	d := make([]byte, 32)

	b.SetBytes(int64(size * num))
	b.StartTimer()

	for i := 0; i < b.N; i++ {
		h.Reset()
		for j := 0; j < num; j++ {
			_, _ = h.Write(data)
		}
		h.Read(d)
	}
}

func BenchmarkShake128_MTU(b *testing.B)  { benchmarkShake(b, NewShake128(), 1350, 1) }
func BenchmarkShake256_MTU(b *testing.B)  { benchmarkShake(b, NewShake256(), 1350, 1) }
func BenchmarkShake256_16x(b *testing.B)  { benchmarkShake(b, NewShake256(), 16, 1024) }
func BenchmarkShake256_1MiB(b *testing.B) { benchmarkShake(b, NewShake256(), 1024, 1024) }

// BenchmarkPermutationFunction measures the speed of the permutation function
// with no input data.
func BenchmarkPermutationFunction(b *testing.B) {
	b.SetBytes(int64(200))
	var lanes keccak.Lanes
	for i := 0; i < b.N; i++ {
		lanes.PermuteWith1600()
	}
}

// debugCapacity returns the capacity lanes.
// FOR TESTING / DEMONSTRATION ONLY.
func (s *State) debugCapacity() []uint64 {
	rateLanes := s.rate / 8
	return s.lanes[rateLanes:]
}

func TestCapacityHidden(t *testing.T) {
	s := NewShake128()
	s.Write([]byte("Hello World"))
	s.Read(make([]byte, 32))

	capacity := s.debugCapacity()
	for i, lane := range capacity {
		t.Logf("capacity lane %d: %016x", i, lane)
	}
}

func TestHelloWorldHash(t *testing.T) {
	msg := "Hello World"
	for _, paradigm := range []string{"SHA3-224", "SHA3-256", "SHA3-384", "SHA3-512", "SHAKE128", "SHAKE256"} {
		var s State
		switch paradigm {
		case "SHA3-224":
			s = New224()
		case "SHA3-256":
			s = New256()
		case "SHA3-384":
			s = New384()
		case "SHA3-512":
			s = New512()
		case "SHAKE128":
			s = NewShake128()
		case "SHAKE256":
			s = NewShake256()
		}
		h := make([]byte, 64)
		msgBytes := []byte(msg)
		s.Write(msgBytes)
		s.Read(h[:])
		fmt.Println("Paradigm = ", paradigm, " - hashBlocks = ", h)
	}
}
