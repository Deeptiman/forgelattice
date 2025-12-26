package sha3

import "github.com/Deeptiman/forgekey/go/src/sha3/keccak"

type Sponge int

const (
	Absorbing Sponge = 1
	Squeezing Sponge = 2
	maxBit    int    = 168

	dsbyteShake = 0x1f
	rate128     = 168
	rate256     = 136
)

type State struct {
	lanes       [25]uint64 // 64-bit lanes
	rate        int        // rate of bytes gets absorbed
	dsbyte      byte       // domain-separator bytes
	buffOffSets int
	parcel      [maxBit]byte
	outputLen   int // the default output size in bytes
	spong       Sponge
}

func NewShake128() State {
	return State{rate: rate128, dsbyte: dsbyteShake, spong: Absorbing}
}

func NewShake256() State {
	return State{rate: rate256, dsbyte: dsbyteShake, spong: Absorbing}
}

func New224() State {
	return State{rate: 144, outputLen: 28, dsbyte: 0x06}
}

func New256() State {
	return State{rate: 136, outputLen: 32, dsbyte: 0x06}
}

func New384() State {
	return State{rate: 104, outputLen: 48, dsbyte: 0x06}
}

func New512() State {
	return State{rate: 72, outputLen: 64, dsbyte: 0x06}
}

func ShakeSum256(hash, data []byte) {
	h := NewShake256()
	_, _ = h.Write(data)
	h.Read(hash)
}

func (s *State) Write(data []byte) (written int, err error) {
	var block []byte
	written = len(data)
	for len(data) > 0 {
		block, data = s.absorbBytes(data)

		copy(s.parcel[s.buffOffSets:], block)
		s.buffOffSets += len(block)

		if s.buffOffSets > s.rate {
			s.buffOffSets = s.rate
		}

		if s.buffOffSets == s.rate {
			s.permute()
		}
	}
	return written, nil
}

func (s *State) Read(out []byte) {
	if s.spong == Absorbing {
		s.padAndPermute(s.dsbyte)
	}

	squeeze := 0
	for len(out) > 0 {
		n := copy(out, s.parcel[:s.buffOffSets])
		out = out[n:]
		squeeze += n

		if squeeze == s.buffOffSets {
			s.permute()
		}
	}
}

func (s *State) absorbBytes(input []byte) ([]byte, []byte) {
	maxRate := s.rate
	if maxRate > len(input) {
		maxRate = len(input)
	}
	return input[:maxRate], input[maxRate:]
}

func (s *State) buf() []byte {
	return s.parcel[:s.buffOffSets]
}

func (s *State) permute() {
	switch s.spong {
	case Absorbing:
		s.xorIn(s.buf())
		s.buffOffSets = 0
		keccak.PermuteWith1600(&s.lanes)
	case Squeezing:
		keccak.PermuteWith1600(&s.lanes)
		s.buffOffSets = s.rate
		s.copyOut(s.buf())
	}
}

func (s *State) padAndPermute(dsbyte byte) {
	padIndexes := s.buffOffSets + 1
	s.buffOffSets = s.rate
	buf := s.buf()
	buf[padIndexes-1] = dsbyte
	for i := padIndexes; i < s.rate; i++ {
		buf[i] = 0
	}
	buf[s.rate-1] ^= 0x80 // XORing the last-bit with 128
	s.permute()
	s.spong = Squeezing
	s.buffOffSets = s.rate
	s.copyOut(buf)
}

func (s *State) clone() *State {
	ret := *s
	return &ret
}

// Sum applies padding to the hash state and then squeezes out the desired
// number of output bytes.
func (s *State) Sum(in []byte) []byte {
	// Make a copy of the original hash so that caller can keep writing
	// and summing.
	dup := s.clone()
	hash := make([]byte, dup.outputLen)
	dup.Read(hash)
	return append(in, hash...)
}

func (s *State) Reset() {
	for i := range s.lanes {
		s.lanes[i] = 0
	}
	s.spong = Absorbing
	s.buffOffSets = 0
}
