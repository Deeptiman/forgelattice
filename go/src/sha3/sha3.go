package sha3

import (
	"github.com/Deeptiman/forgekey/go/src/sha3/keccak"
)

// SpongePhase represents the current phase of the sponge construction.
type SpongePhase int

const (
	// Absorbing indicates that input data is being absorbed.
	Absorbing SpongePhase = iota
	// Squeezing indicates that output data is being produced.
	Squeezing
)

const (
	// Maximum rate in bytes (SHAKE128).
	maxRateBytes int = 168

	// Domain separation bytes.
	// These distinguish SHAKE from fixed-length SHA-3 hashes.
	dsbyteShake  = 0x1f
	dsbyteShake2 = 0x06

	// Default output sizes for fixed-length SHA-3 hashes.
	outputLenSHA3_224 = 28
	outputLenSHA3_256 = 32
	outputLenSHA3_384 = 48
	outputLenSHA3_512 = 64

	// SpongePhase rates in bytes for each SHA-3 variants.
	rate128 = 168
	rate224 = 144
	rate384 = 104
	rate512 = 72
	rate256 = 136
)

// State represents the internal state of the SHA-3 / SHAKE sponge.
type State struct {
	// lanes: Keccak-f[1600] state (5x5 lanes of 64 bits).
	lanes keccak.Lanes
	// rate: Number of bytes absorbed/sequeezed per block.
	rate int
	// dsbyte: Domain-separator byte.
	dsbyte byte
	// bufLen: Number of buffered bytes.
	bufLen int
	// rateBuf: Maximum rate-sliced buffer bytes.
	rateBuf [maxRateBytes]byte
	// outputLen: Default output size for fixed-length hashes.
	outputLen int
	// phase: Current sponge phase.
	phase SpongePhase
}

// NewShake128 returns a new SHAKE128 sponge state.
func NewShake128() State {
	return State{rate: rate128, dsbyte: dsbyteShake, phase: Absorbing}
}

// NewShake256 returns a new SHAKE256 sponge state.
func NewShake256() State {
	return State{rate: rate256, dsbyte: dsbyteShake, phase: Absorbing}
}

// New224 returns a new SHA-3-224 sponge state.
func New224() State {
	return State{rate: rate224, dsbyte: dsbyteShake2, outputLen: outputLenSHA3_224}
}

// New256 returns a new SHA-3-256 sponge state.
func New256() State {
	return State{rate: rate256, dsbyte: dsbyteShake2, outputLen: outputLenSHA3_256}
}

// New384 returns a new SHA-3-384 sponge state.
func New384() State {
	return State{rate: rate384, dsbyte: dsbyteShake2, outputLen: outputLenSHA3_384}
}

// New512 returns a new SHA-3-512 sponge state.
func New512() State {
	return State{rate: rate512, dsbyte: dsbyteShake2, outputLen: outputLenSHA3_512}
}

// ShakeSum256 computes a SHAKE256 digest of the data into hash.
func ShakeSum256(hash, data []byte) {
	h := NewShake256()
	_, _ = h.Write(data)
	h.Read(hash)
}

// Write absorbs input data into the sponge.
//
// Data is buffered until a full rate of block is available then XORed into the Keccak state followed
// by a permutation.
func (s *State) Write(data []byte) (written int, err error) {
	var block []byte
	written = len(data)
	for len(data) > 0 {
		block, data = s.absorbBytes(data)

		copy(s.rateBuf[s.bufLen:], block)
		s.bufLen += len(block)

		if s.bufLen == s.rate {
			s.permute()
		}
	}
	return written, nil
}

// Read squeezes output bytes from the sponge.
//
// If the sponge is still in the absorbing phase, padding is applied and the state transitioned to
// squeezing.
func (s *State) Read(out []byte) {
	if s.phase == Absorbing {
		s.padAndPermute(s.dsbyte)
	}

	consumed := 0 // track how many bytes of the current absorbed block have been consumed.
	for len(out) > 0 {
		n := copy(out, s.buf())
		consumed += n
		out = out[n:]

		if consumed == s.bufLen {
			s.permute()
		}
	}
}

// absorbBytes returns the maximum input slice that fits into the rate buffer.
func (s *State) absorbBytes(input []byte) ([]byte, []byte) {
	maxRate := s.rate - s.bufLen
	if maxRate > len(input) {
		maxRate = len(input)
	}
	return input[:maxRate], input[maxRate:]
}

// buf returns the active portion of the rate buffer.
func (s *State) buf() []byte {
	return s.rateBuf[:s.bufLen]
}

// permute applies the Keccak-f[1600] permutation depending on sponge phase.
func (s *State) permute() {
	switch s.phase {
	case Absorbing:
		// XOR buffered input into the state then permute.
		s.xorIn(s.buf())
		s.bufLen = 0
		s.lanes.PermuteWith1600()
	case Squeezing:
		// Permute state and extract new output block.
		s.lanes.PermuteWith1600()
		s.bufLen = s.rate
		s.copyOut(s.buf())
	}
}

// padAndPermute applies domain separation and multi-rate padding then transition the sponge from
// absorbing to squeezing.
func (s *State) padAndPermute(dsbyte byte) {
	padIndex := s.bufLen
	s.bufLen = s.rate
	buf := s.buf()
	buf[padIndex] = dsbyte
	for i := padIndex + 1; i < s.rate; i++ {
		buf[i] = 0
	}

	// Final padding bit.
	buf[s.rate-1] ^= 0x80 // XORing the last-bit with 128

	s.permute()
	s.phase = Squeezing
	s.bufLen = s.rate
	s.copyOut(buf)
}

// clone returns a shallow copy of the sponge state.
func (s *State) clone() *State {
	ret := *s
	return &ret
}

// Sum finalizes the sponge and returns the fixed-length hash output.
func (s *State) Sum(in []byte) []byte {
	dup := s.clone()
	hash := make([]byte, dup.outputLen)
	dup.Read(hash)
	return append(in, hash...)
}

// Reset clears the sponge state for reuse.
func (s *State) Reset() {
	for i := range s.lanes {
		s.lanes[i] = 0
	}
	s.phase = Absorbing
	s.bufLen = 0
}
