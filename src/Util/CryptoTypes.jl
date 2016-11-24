# Types declarations for Krypto.jl
# Copyright (C): Jaka Smrekar (vinctux) <vinctux@outlook.com>, 2016

# Primitives
abstract CryptoAlgorithm
abstract SymmetricCrypto <: CryptoAlgorithm
abstract AsymmetricCrypto <: CryptoAlgorithm

# Asymmetric
abstract RSA <: AsymmetricCrypto
abstract ECC <: AsymmetricCrypto
abstract RLWE <: AsymmetricCrypto
abstract NTRU <: AsymmetricCrypto

# Symmetric
abstract AES <: SymmetricCrypto
abstract Blowfish <: SymmetricCrypto
abstract Twofish <: SymmetricCrypto
abstract Threefish <: SymmetricCrypto
abstract Serpent <: SymmetricCrypto
abstract Salsa20 <: SymmetricCrypto
abstract RABBIT <: SymmetricCrypto
