package sha3

type Sponge int

const (
	Absorbing Sponge = iota
	Squeezing
	maxBit int = 168

	dsbyteShake = 0x1f
	rate128     = 168
	rate256     = 136
)

type State struct {
	lanes       [25]uint64 // 64-bit lanes
	rate        int        // rate of bytes gets absorbed
	dsBytes     byte       // domain-separtor bytes
	buffOffSets int
	parcel      [maxBit]byte
	spong       Sponge
}

func NewShake128() State {
	return State{rate: rate128, dsBytes: dsbyteShake, spong: Absorbing}
}

func NewShake256() State {
	return State{rate: rate256, dsBytes: dsbyteShake, spong: Absorbing}
}

func (s *State) Write(data []byte) (written int, err error) {
	var block []byte
	written = len(data)
	for len(data) > 0 {
		block, data = s.absorbBytes(data)

		copy(s.parcel[s.buffOffSets:], block)
		s.buffOffSets += len(block)

		if s.buffOffSets == s.rate {
			s.permute()
		}
	}
	return written, nil
}

func (s *State) Read(out []byte) error {
	if s.spong == Absorbing {
		s.padAndPermute(s.dsBytes)
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
	case Absorbing:
		s.xorIn(s.buf())
		s.buffOffSets = 0
		KeccakF1600(&s.lanes)
	case Squeezing:
		KeccakF1600(&s.lanes)
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
