// Package sha3 implements the SHA-3 / SHAKE sponge construction on the top of the Keccak-f[1600] permutation.
//
// Specifications: FIPS 202 (SHA-3 Standard: Permutation-Based Hash and Extendable-Output Functions)
//   - https://csrc.nist.gov/files/pubs/fips/202/final/docs/fips_202_draft.pdf
//
// The sponge operates in two phases:
//
//  1. Absorbing: input bytes are XORed into the state and permuted.
//  2. Squeezing: output bytes are read from the state with permutations applied as needed.
//
// The State type maintains the Keccak lanes, rate, domain separation, buffering and sponge phases.
package sha3
