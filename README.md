Krypto.jl
=========
A futuristic crypto library. In Julia.

100% pure [Julia](https://github.com/JuliaLang/julia) implementations of most popular cryptographic algorithms. Contains native implementations of PQC ([Post-Quantum Cryptography](https://en.wikipedia.org/wiki/Post-quantum_cryptography)). Contributions welcome.

## Disclaimer
**WARNING: This package is an ALPHA and is NOT yet ready for production use. Its current state is more like a PoC implementation. Proceed at your own risk.**

## Current features
- 100% native Julia implementations. No wrappers. No non-Julia dependencies.
- Support for RSA (working primitives, [PKCS#1](https://en.wikipedia.org/wiki/PKCS_1) not working)
- Support for RLWE (non-tested primitives)
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

## Quality note
[I (vinctux)](https://github.com/vinctux) do my best to make this code work properly and in a secure manner but as I currently do not hold a degree in Cryptography or simmiliar, some could say I do not have the required knowledge to build such a library. I somehow agree with that. I'm not the person who would be called first for this job. But eventually, nobody did a native Julia cryptography library yet. So I decided to do it. IMHO, holding a degree doesn't make your words facts yet. You (as the user) shouldn't blindly trust this code. As a passionated hobby cryptographer, I do know about cryptography pretty something but eventually severe vulnarbities CAN happen.

Oh, a friendly recommendation: DON'T ULTIMATELLY TRUST _ANY_ code with your life.
Cryptography or anything else.

## License
MIT. Whatever happens to you, remember: it's not my fault but the code you used is. ¯\\_(ツ)_/¯
