package kyber

// Kyber Key Generation
//
// --------------------------------
//
// Kyber512 ---> ~128-bit security --> Public key-size : 800 bytes
// Kyber768 ---> ~192-bit security --> Public key-size : 1184 bytes
// Kyber1024 ---> ~256-bit security --> Public key-size : 1568 bytes
//
// Common:
// N = 256
// q = 3329
// Polynomial ring: Z_q[x]/(x²⁵⁶+ 1)
// Keccack-based randomness only
//
// ---------------------------------------------
//
// Flow:
//
//  1. Random seed (32-bytes) from Secure RNG
//
//  2. Seed Expansion SHA3-512 (seed):
//     Output:
//     - ρ (public seed)
//     - σ (secret seed)
//
//  3. Generate Public Matrix A
//     - SHAKE128(ρ) => A ∈ R_q^{kxk}
//
//  4. Secret (s) & Error (e) Sampling
//     - SHAKE256(σ) => s, e ∈ R_q^k
//
//  5. Core LWE Computation
//
//     t = A . s + e
//
//     (NTT + Montgomery arithmetic)
//
// 6. Key Encoding
//
// Public Key: pk = (t || ρ)
// Secret Key: sk = s
