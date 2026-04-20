## ForgeKey
An independent research project focused on building Post-Quantum Cryptographic (PQC) protocols by referencing 
NIST-validated algorithms. The soft-core is written entirely in Go.

### Goal
This repository serves as the **software reference layer** for ForgeKey — a long-term personal research project 
aimed at building a secure, auditable, post-quantum hardware wallet.

### Current Modules (Verified with Official KAT Vectors)
All modules have been tested against official NIST Known Answer Test (KAT) vectors for correctness:

- **Kyber-KEM** - CRYSTALS-Kyber (NIST FIPS-203)
- **Dilithium-DSA** - CRYSTALS-Dilithium (NIST FIPS-204)
- **SHA-3 / Keccak** - SHA3-256, SHA3-512, SHAKE128, SHAKE256 (NIST FIPS-202)

### Why CIRCL as Reference?
CIRCL (Cloudflare Interoperable Cryptographic Library) was used as a trusted reference implementation during development.

This repository is **not a fork** of CIRCL. It is a clean re-implementation written from first principles for deeper 
understanding and clarity. CIRCL’s official Known Answer Test (KAT) vectors were used extensively to validate 
correctness across different security levels.


