package sha3

type Sponge int

const (
	Absorb Sponge = iota
	Squeeze
	maxBit int = 168
)

type State struct {
	lanes       [25]uint64 // 64-bit lanes
	rate        int        // rate of bytes gets absorbed
	dsBytes     byte       // domain-separtor bytes
	buffOffSets int
	parcel      [maxBit]byte
	spong       Sponge
}

func (s *State) Hash(data []byte) error {
	var block []byte
	for len(data) > 0 {
		block, data = s.absorbBytes(data)

		s.buffOffSets += len(block)
		copy(s.parcel[len(s.parcel):], block)

		if s.buffOffSets == s.rate {
			s.permute()
		}
	}
	return nil
}

func (s *State) Read(out []byte) error {
	if s.spong == Absorb {
		s.padding()
	}
	for len(out) > 0 {
		n := copy(out, s.parcel[:s.buffOffSets])
		out = out[n:]
	}
	return nil
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
	case Absorb:
		s.xorIn(s.buf())
		s.buffOffSets = 0
		KeccakF1600(&s.lanes)
	case Squeeze:
		KeccakF1600(&s.lanes)
		s.buffOffSets = s.rate
		s.copyOut(s.buf())
	}
}

func (s *State) padding() {
	s.parcel[s.buffOffSets-1] ^= 0x01
	for i := s.buffOffSets; i < s.rate; i++ {
		s.parcel[i] = 0
	}
	s.parcel[s.rate-1] = 0x1f
	s.permute()
	s.spong = Squeeze
	s.buffOffSets = s.rate
	s.copyOut(s.buf())
}
