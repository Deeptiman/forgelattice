package sha3

import (
	"encoding/binary"
)

// xorIn XORs a rate-sized block into the Keccak state.
//
// The input block is interpreted as little-endian 64-bit words and XORed lane-by-lane into the state.
// Only the first rate/8 lanes are modified, the remaining lanes forms the sponge capacity and are
// untouched.
//
// This function is used during the absorbing phase of the sponge.
func (s *State) xorIn(block []byte) {
	bits := len(block) / 8
	for i := 0; i < bits; i++ {
		s.lanes[i] ^= binary.LittleEndian.Uint64(block)
		block = block[8:]
	}
}

// copyOut copies output from the Keccak state into the provided buffer.
//
// State lanes are written in little-endian order one lane (8 bytes) at a time. And only the rate
// portion of the state is exposed, capacity lanes are never copied out.
//
// This function is used during the squeezing phase of the sponge.
func (s *State) copyOut(b []byte) {
	for i := 0; len(b) >= 8; i++ {
		binary.LittleEndian.PutUint64(b, s.lanes[i])
		b = b[8:]
	}
}
