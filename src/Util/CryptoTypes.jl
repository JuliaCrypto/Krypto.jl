# Types declarations for Krypto.jl
# Copyright (C): Jaka Smrekar (vinctux) <vinctux@outlook.com>, 2016

using Krypto

# Primitives
abstract CryptoAlgorithm
abstract SymmetricCryptoAlgorithm <: CryptoAlgorithm
abstract AsymmetricCryptoAlgorithm <: CryptoAlgorithm

# Asymmetric algorithms
abstract RSA <: AsymmetricCryptoAlgorithm
abstract ECC <: AsymmetricCryptoAlgorithm
abstract RLWE <: AsymmetricCryptoAlgorithm
abstract NTRU <: AsymmetricCryptoAlgorithm

# Symmetric (only non-stream for now)
abstract AES <: SymmetricCryptoAlgorithm
abstract Blowfish <: SymmetricCryptoAlgorithm
abstract Twofish <: SymmetricCryptoAlgorithm
abstract Threefish <: SymmetricCryptoAlgorithm
abstract Serpent <: SymmetricCryptoAlgorithm
