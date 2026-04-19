// Package dsa implements Module Lattice Digital Signature Algorithm (ML-DSA) (Dilithium) scheme.
//
// WARNING:
//
// This package is an INTERNAL cryptographic primitive. It MUST NOT be used directly by applications,
// protocols, or external packages. Direct use may lead to misuse and compromise of security guarantees.
//
// This implementation is intended to be used by higher-level digital signature standard such as
// ML-DSA (FIPS-204).
//
// # Overview
//
// ML-DSA (Dilithium) is a lattice-based digital signature scheme based on the hardness of the Module Learning
// With Errors (Module-LWE) and Module Short Integer Solution (Module-SIS) problems. It uses a Fiat-Shamir
// with aborts paradigm to achieve strong unforgeability. The scheme operates over polynomial rings with efficient
// arithmetic using the Number Theoretic Transform (NTT).
//
// # Security Model
//
// - SUF-CMA (Strongly existentially UnForgeable under Chosen Message Attack)
// - Designed to be secure against adversaries with large-scale quantum capabilities.
// - Security relies on Module-LWE and Module-SIS lattice-cryptographic paradigms.
//
// # Design Arithmetic
//
// - Polynomial arithmetic is performed modulo q = 8380417 and ring dimension n = 256.
// - Extensive use of Number Theoretic Transform (NTT) for point-wise computations of polynomials.
// - Rejection sampling is used in signing (Fiat-Shamir with aborts).
// - Packing and compression follow ML-DSA (Dilithium) specifications.
//
// # Specification
//
// - FIPS 204 (ML-DSA):
// https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.204.pdf
//
// - CRYSTALS-Dilithium Specification:
// https://pq-crystals.org/dilithium/data/dilithium-specification-round3.pdf
//
// # Usage
//
// This package is consumed internally by:
// - sign/mldsa/fips204
package dsa
