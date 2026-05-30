# ForgeLattice

[![Go Version](https://img.shields.io/badge/Go-1.26-blue.svg)](https://go.dev/)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![PQC](https://img.shields.io/badge/Post--Quantum-Cryptography-8B00FF.svg)]()
[![Status](https://img.shields.io/badge/Status-Experimental-orange.svg)]()

**An independent open-source research project** on Post-Quantum Cryptography (PQC) in Go. This library provides clean, well-structured implementation of
NIST standardized PQC algorithms, designed as a **software service layer** for learning, experimentation, integration, and future hardware acceleration research.

### Key Features

- Written directly from official NIST specifications. ([FIPS-203](https://pq-crystals.org/kyber/data/kyber-specification-round3.pdf), [FIPS-204](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.204.pdf), [FIPS-202](https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.202.pdf)).
- Independent research implementation of NIST-standardized Post-Quantum Cryptography.
- Uses [CIRCL (Cloudflare Interoperable, Reusable Cryptographic Library)](https://github.com/cloudflare/circl) as a trusted reference for validation.
- Rigorously validated against official **NIST KAT test vectors**.
- Clean, idiomatic Go code with strong emphasis on readability and correctness.
- Practical CLI tool `fl` included for quick demonstration and usage.

### Security Disclaimer

**⚠️ CAUTION: Do not use this library in any system where cryptographic security is required**

ForgeLattice is an **experimental research library**.

- The code is validated with NIST KAT vectors but has **NOT** undergone formal cryptographic review, side-channel analysis, or constant-time verification.
- It is not recommended for use in any production, security-critical infrastructures or real world deployments.
- This library is provided strictly for **educational, learning and research purpose only**.

Use it at your own risk.

### Currently Supported Algorithms

| Algorithm              | NIST Standard          | Security Levels                  | Module Path                     |
|------------------------|------------------------|----------------------------------|---------------------------------|
| CRYSTALS-Kyber         | FIPS-203 (ML-KEM)      | 512, 768, 1024                   | `crypto/kem/kyber`              |
| CRYSTALS-Dilithium     | FIPS-204 (ML-DSA)      | **44, 65, 87** (ML-DSA-44/65/87) | `crypto/sign/dilithium`         |
| SHA-3 / Keccak         | FIPS-202               | SHAKE128, SHAKE256               | `crypto/sha3`                   |

### CLI Tool (`fl`)

A simple command line tool to demonstrate practical usage of the library.

**Build the CLI**
```bash
go build -o fl ./examples/fl
````

**Examples**
`````````bash
./fl help                                                                                                                                         git:dev-go-version*
fl (ForgeLattice) -- Post-Quantum Cryptography Command Line Tool

Usage:
   [flags]
   [command]

Available Commands:
  completion  Generate the autocompletion script for the specified shell
  dsa         CRYSTALS-Dilithium (ML-DSA) operations
  help        Help about any command
  kem         CRYSTALS-Kyber (ML-KEM) operations

Flags:
  -h, --help   help for this command

Use " [command] --help" for more information about a command.

./fl help kem                                                                                                                                     git:dev-go-version*
CRYSTALS-Kyber (ML-KEM) operations

Usage:
   kem [command]

Available Commands:
  decaps      Kyber Decapsulation Mechanism (Recover shared secret)
  encaps      Kyber Key Encapsulation Mechanism.
  keygen      Generate a Kyber keypair

Flags:
  -h, --help   help for kem

Use " kem [command] --help" for more information about a command.

./fl help dsa                                                                                                                                     git:dev-go-version*
CRYSTALS-Dilithium (ML-DSA) operations

Usage:
   dsa [command]

Available Commands:
  keygen      Generate a Dilithium keypair
  sign        Sign a message using Dilithium
  verify      Verify a signature using Dilithium

Flags:
  -h, --help   help for dsa

Use " dsa [command] --help" for more information about a command.
`````````

### Watch Demo

*CRYSTALS-Kyber (ML-KEM) operations*

[![asciicast](https://asciinema.org/a/nQys9YkDVBJaUNGp.svg)](https://asciinema.org/a/nQys9YkDVBJaUNGp)

*CRYSTALS-Dilithium (ML-DSA) operations*

[![asciicast](https://asciinema.org/a/dO6qBs3lOxsJGl8F.svg)](https://asciinema.org/a/dO6qBs3lOxsJGl8F)

### Installation
```
 go get github.com/Deeptiman/forgelattice/crypto
```

### Testing
You can each module separately by running the package-level `go-test`

**Test SHA3 / Keccak**
````
make test-sha3
````

**Test Kyber (ML-KEM)**
````
make test-kem
````

**Test Dilithium (ML-DSA)**
````
make test-dsa
````

**Test all crypto module**
````
make test-all
````

## LICENSE
This project is licensed under the [MIT License](https://github.com/Deeptiman/forgelattice/blob/main/LICENSE)
