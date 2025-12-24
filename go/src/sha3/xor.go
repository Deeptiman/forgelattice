package sha3

import "encoding/binary"

func (s *State) xorIn(block []byte) {
	bits := len(block) / 8
	for i := 0; i < bits; i++ {
		s.lanes[i] ^= binary.LittleEndian.Uint64(block)
		block = block[8:]
	}
}

func (s *State) copyOut(b []byte) {
	for i := 0; len(b) >= 8; i++ {
		binary.LittleEndian.PutUint64(b, s.lanes[i])
		b = b[8:]
	}
}
