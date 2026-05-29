// Package cpapke implements the Kyber Chosen Plaintext Attack (CPA) secure Public-Key Encryption (CPAPKE)
// primitive.
//
//	WARNING:
//
//	This package is an INTERNAL cryptographic primitive. It MUST NOT be used directly by application, protocols, or
//	by any package layers. The direct invocation to this package method is NOT CCA-secure.
//
// This implementation is intended to be used exclusively by higher-level constructions such as ML-KEM (FIPS203), which
// apply the Fujisaki-Okamoto transform to achieve Indistinguishable Chosen Ciphertext Attack (IND-CCA2) security.
//
// # Overview
//
//	Kyber CPAPKE is a lattice-based public-key encryption scheme that provides IND-CPA security. The computation
//	is performed over polynomial rings using Number Theoretic Transform (NTT) for efficient multiplication.
//
// # Security Model
//
//   - IND-CPA secure ONLY
//   - NOT secure against adaptive chosen-ciphertext attacks
//   - MUST be wrapped by ML-KEM before external exposure
//
// # Design Arithmetic
//
//   - Polynomial arithmetic is performed modulo q = 3329
//   - All secrets are represented in the NTT domain.
//   - Packing and compression follow Kyber Round-3 specifications.
//
// # Specification
//
//   - Kyber Round 3 Specification:
//     https://pq-crystals.org/kyber/data/kyber-specification-round3.pdf
//
// # Usage
//
//	This package is consumed internally by:
//	- kem/protocol/fips203
package cpapke
