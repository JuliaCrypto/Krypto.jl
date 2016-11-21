# Ring Learning with Errors (RLWE) implementation in Julia
# Copyright (C): Jaka Smrekar (vinctux) <vinctux@outlook.com>, 2016
#
# Reference:       https://eprint.iacr.org/2014/725.pdf
#                  https://eprint.iacr.org/2015/138.pdf
#                  https://eprint.iacr.org/2016/049.pdf
#                  https://securewww.esat.kuleuven.be/cosic/publications/article-2444.pdf
#                  https://www.microsoft.com/en-us/research/wp-content/uploads/2016/05/RLWE-1.pdf
# x86 C reference: https://github.com/ruandc/Ring-LWE-Encryption/blob/master/x86

using Krypto
using Polynomials

abstract RLWEKey

type RLWEPubKey <: RLWEKey
    A::Poly
    P::Poly
    N::Integer
    Q::LatticeModuli
end

type RLWEPrivKey <: RLWEKey
    R::Poly
    N::Integer
    Q::LatticeModuli
end

global const B = 12                       # Global sampling bound B
global const Q = LatticeModuli(3, 11, 1)  # Global moduli (== 12289)

# Generates RLWE keypair
function RLWEKeyGen(A::Poly, N::Integer = 1024)
    R1 = UniformSample(B, N)
    R2 = GenerateR2(N)
    P = R1 - A * R2
    println("$(P)")
    return RLWEPubKey(NTTK(A, Q, N), NTTK(P, Q, N), N, Q), RLWEPrivKey(NTTK(R2, Q, N), N, Q)
end

# RLWE Encryption primitive
function RLWEEncrypt(K::RLWEPubKey, M::Poly)
    ERR = [UniformSample(B, K.N) for i in 1:3]
    E1, E2 = NTTK(ERR[1], K.Q, K.N), NTTK(ERR[2], K.Q, K.N)
    return K.A * E1 + E2, K.P * E1 + NTTK(ERR[3] + M, K.Q, K.N)
end
RLWEEncrypt(K::RLWEPubKey, M::Array{UInt8, 1}) = RLWEEncrypt(K, bytes2poly(M))

# RLWE Decryption primitive
RLWEDecrypt(K::RLWEPrivKey, C1::Poly, C2::Poly) = INTTK(C1 * K.R + C2, K.Q, K.N)
RLWEDecrypt(K::RLWEPrivKey, C::Tuple{Poly, Poly}) = RLWEDecrypt(K, C[1], C[2])
RLWEDecrypt(K::RLWEPrivKey, C1::Array{UInt8, 1}, C2::Array{UInt8, 1}) = RLWEDecrypt(K, bytes2poly(C1), bytes2poly(C2))

function encrypt(::Type{Krypto.RLWE}, K::RLWEPubKey, M::Array{UInt8, 1})
    C1, C2 = RLWEEncrypt(K, M)
    # 0xff || n° of C1 || 0x00 || C1 || 0x00 × 8 || n° of C2 bytes || 0x00 || C2 || 0xff
    return vcat([0o377], [UInt8(degree(C1))], poly2bytes(C1), [0o0 for i in 1:8], [UInt8(degree(C2))], poly2bytes(C2), [0o377])
end

function decrypt(::Type{Krypto.RLWE}, K::RLWEPrivKey, M::Array{UInt8, 1})
    if M[1] != 0o377 || M[end] != 0o377 error("Decryption error.") end
    i, S1 =  2, 0
    while M[i] != 0o0 S1 += Int64(M[i]) * 256^(i - 1) end
    C1 = M[3:S1]
    if M[S1:(S1 + 8)] != [0o0 for i in 1:8] error("Decryption error.") end
    i, S2 =  S1 + 8, 0
    while M[i] != 0o0 S2 += Int64(M[i]) * 256^(i - S1 - 7) end
    C2 = M[(S1 + 8):(S1 + S2 + 8)]
    if M[end] != M[S1 + S2 + 8] || M[end] != 0o377 error("Decryption error.") end
    return poly2bytes(RLWEDecrypt(K, C1, C2))
end
