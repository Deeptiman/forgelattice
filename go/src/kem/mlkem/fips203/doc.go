// Package fips203 implements the ML-KEM (Module-Lattice KEM) protocol as standardized in NIST FIPS-203.
//
// # Overview
//
// ML-KEM is a CCA-secure Key Encapsulation Mechanism derived from the Kyber CPA-secure public-key encryption
// (CPAPKE) primitive using the Fujisaki-Okamoto transform.
//
// Specifications:
//
//   - NIST FIPS 203:
//     https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.pdf
//
//   - Kyber Round 3 Specification:
//     https://pq-crystals.org/kyber/data/kyber-specification-round3.pdf
//
// Security Properties:
//   - IND-CCA2 security (via Fujisaki-Okamoto transform)
//   - Constant-time decapsulation
//   - Domain separation between ML-KEM parameter sets.
//   - Deterministic key generation and compliance testing with deterministic seeds from Known Answer Test (KAT).
//
// Key Security Design:
//
// 1. Domain Separation
//
// FIPS 203 requires the Kyber parameter K to be injected into the key-generation seed. This additional byte of seed
// will enforce domain-separation to prevent seed collision between Kyber schemes or key reuse.
//
// 2. Constant-Time Decapsulation
//
// Decapsulation always executes both success and failure paths. If ciphertext hash comparison fails, a pseudorandom
// function (PRF) returns a key derived from PrivateKey secret value z and Ciphertext {PRF(z || ct)}.
//
// Usage:
//
// This package is intended to be consumed via a higher-level KEM API.
//
// Structures:
//   - Protocol
//   - PrivateKey
//   - PublicKey
//
// Typical flow:
//
// proto := fips203.New(Kyber_Level)
// pk, sk := proto.GenerateKeyPair(seed)
// ct, ss1 := proto.Encapsulate(pk, coin)
// ss2 := proto.Decapsulate(sk, ct)
//
// Protocol validation succeeds only if ss1 == ss2
package fips203
