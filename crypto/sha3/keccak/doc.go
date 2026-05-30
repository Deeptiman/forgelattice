// Package keccak implements the Keccak-f[1600] permutation.
//
// The state is represented as a 5x5 array of 64-bit lanes (25 uint64 values). The permutation consists
// of 24 rounds, each applying the steps:
//
// θ (Theta) → ρ (Rho) → π (Pi) → χ (Chi) → ι (Iota)
//
// Specification: FIPS 202 (SHA-3 Standard: Permutation-Based Hash and Extendable-Output Functions)
// - https://csrc.nist.gov/files/pubs/fips/202/final/docs/fips_202_draft.pdf
// - https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf
//
// This package implementation follows the Keccak specification directly and is suitable for SHA-3 and
// SHAKE construction.
package keccak
