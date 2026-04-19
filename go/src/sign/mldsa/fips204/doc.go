// Package fips204 implements the ML-DSA (Module Lattice Digital Signature Algorithm) protocol as standardized
// in NIST FIPS 204.
//
// # Overview
//
// ML-DSA (Dilithium) is a lattice-based digital signature scheme that provides strong unforgeability under
// chosen message attacks (SUF-CMA). It is based on hardness of Module-LWE (Learning With Error) and
// Module-SIS (Short Integer Solution) problems and uses Fiat-Shamir with abort paradigm to achieve security
// in the random oracle model.
//
// Specifications:
//
// - NIST FIPS 204:
// https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.204.pdf
//
// - CRYSTALS-Dilithium Specification:
// https://pq-crystals.org/dilithium/data/dilithium-specification-round3.pdf
//
// Security Properties:
//
// - SUF-CMA (Strongly existentially UnForgeable under Chosen Message Attack)
// - Designed to be secure against adversaries with large-scale quantum capabilities.
// - Security relies on Module-LWE and Module-SIS lattice-cryptographic paradigms.
// - Domain separation across parameter sets and hash invocations.
//
// Key Security Design:
//
// 1. Fiat-Shamir with Aborts
//
// Signing uses rejection sampling to ensure that signature output do not leak key-material information.
// Each signing attempts samples a fresh ephemeral vector y. If the computation arithmetic result exceeds
// defined bounds are discarded and retried.
//
// 2. Deterministic and Hedge Signing
//
// ML-DSA supports deterministic signing (reproducible from tests) and also hedge signing with random source
// beneficial for side-channel resistance.
//
// Usage:
//
// This package is intended to be consumed via higher-level DSA API.
//
// Structures:
//   - Protocol
//   - PrivateKey
//   - PublicKey
//
// Typical flow:
//
// proto := fips204.New(level) // level-> {ML-DSA-44, ML-DSA-65, ML-DSA-87}
// pk, sk := proto.GenerateKeyPair(seed)
// skBytes := proto.MarshalPrivateKey(sk)
// pkBytes := proto.MarshalPublicKey(pk)
// sig := proto.Sign(skBytes, messageBytes, randomBytes)
// ok := proto.Verify(pkBytes, messageBytes, sig)
//
// Verification succeeds only if ok is true.
package fips204
