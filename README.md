Krypto.jl
=========
A futuristic crypto library. In Julia.

100% pure [Julia](https://github.com/JuliaLang/julia) implementations of most popular cryptographic algorithms. Contains native implementations of PQC ([Post-Quantum Cryptography](https://en.wikipedia.org/wiki/Post-quantum_cryptography)). Contributions welcome.

## Disclaimer
**WARNING: This package is in a Proof-of-Concept state and is NOT (yet) ready for production use. Proceed at your own risk.**

## Current features
- 100% native Julia implementations. No wrappers. No non-Julia dependencies.
- Support for RSA (working primitives, [PKCS#1](https://en.wikipedia.org/wiki/PKCS_1) not working)
- Support for RLWE (working crypto-primitives, non-working NTT)
- Support for ECC math (no primitives of yet)

## Algorithms
Implementation status: **complete**, *partial*. The higher an algorithm is listed in a specific section, the more of it is actually implemented.

### Asymmetric
- [**RSA**](https://en.wikipedia.org/wiki/RSA_(cryptosystem)) (non-PQC)
- [*RLWE*](https://en.wikipedia.org/wiki/Ring_Learning_with_Errors) (PQC)
- [*ECC*](https://en.wikipedia.org/wiki/Elliptic_curve_cryptography) (non-PQC)
- [NTRU](https://en.wikipedia.org/wiki/NTRU) (PQC)

### Symmetric
#### Block ciphers
- [AES](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard) (Rijndael)
- [Blowfish](https://en.wikipedia.org/wiki/Blowfish_(cipher))
- [Twofish](https://en.wikipedia.org/wiki/Twofish)
- [Threefish](https://en.wikipedia.org/wiki/Threefish)
- [Serpent](https://en.wikipedia.org/wiki/Serpent_(cipher))

#### Stream ciphers
- [Salsa20](https://en.wikipedia.org/wiki/Salsa20)
- [Rabbit](https://en.wikipedia.org/wiki/Rabbit_(cipher))

## Dependencies
`Krypto.jl` requires some packages to run properly. Besides the `julia` binary, you'll need the following.
- `SHA` (general use of SHA), at least `0.3`
- `Primes` (needed by RSA and others), at least `0.1.1`

## License
MIT. Whatever happens to you, remember: it's not my fault but the code you used is. ¯\\_(ツ)_/¯
