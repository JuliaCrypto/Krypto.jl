# Ring Learning with Errors (RLWE) implementation in Julia
# Copyright (C): Jaka Smrekar (vinctux) <vinctux@outlook.com>, 2016
#
# Reference:       https://eprint.iacr.org/2014/725.pdf
#                  https://eprint.iacr.org/2015/138.pdf
#                  https://eprint.iacr.org/2016/049.pdf
#                  https://securewww.esat.kuleuven.be/cosic/publications/article-2444.pdf
# x86 C reference: https://github.com/ruandc/Ring-LWE-Encryption/blob/master/x86

using Krypto
using Polynomials

abstract RLWEKey

type RLWEPubKey <: RLWEKey
    A::Poly
    P::Poly
    N::Integer
    Q::Integer
end

type RLWEPrivKey <: RLWEKey
    R::Poly
    N::Integer
    Q::Integer
end

B = 16   # Global sampling bound B

# Generates RLWE keypair
function RLWEKeyGen(A::Poly, Q::Integer = 40961, N::Integer = 1024) #::Tuple{RLWEPubKey, RLWEPrivKey}
    R1 = UniformSample(B, N, Q)
    R2 = GenerateR2(N, Q)
    P = R1 - A * R2
    println("$(P)")
    return RLWEPubKey(NTT(A, Q), NTT(P, Q), N, Q), RLWEPrivKey(NTT(R2, Q), N, Q)
end

# RLWE Encryption primitive
function RLWEEncrypt(K::RLWEPubKey, M::Poly) #::Tuple{Poly, Poly}
    ERR = [UniformSample(B, K.N, K.Q) for i in 1:3]
    E1 = NTT(ERR[1])
    E2 = NTT(ERR[2])
    return K.A * E1 + E2, K.P * E1 + NTT(ERR[3] + M)
end
RLWEEncrypt(K::RLWEPubKey, M::Array{UInt8, 1}) = RLWEEncrypt(K, bytes2poly(M))

# RLWE Decryption primitive
RLWEDecrypt(K::RLWEPrivKey, C1::Poly, C2::Poly) = INTT(C1 * K.R + C2)
RLWEDecrypt(K::RLWEPrivKey, C1::Array{UInt8, 1}, C2::Array{UInt8, 1}) = RLWEDecrypt(K, bytes2poly(C1), bytes2poly(C2))

function encrypt(::RLWE, K::RLWEPubKey, M::Array{UInt8, 1}) #::Array{UInt8}
    C1, C2 = RLWEEncrypt(K, M)
    # 0xff || n° of C1 || 0x00 || C1 || 0x00 × 8 || n° of C2 bytes || 0x00 || C2 || 0xff
    return vcat([0o377], [UInt8(degree(C1))], poly2bytes(C1), [0o0 for i in 1:8], [UInt8(degree(C2))], poly2bytes(C2), [0o377])
end

function decrypt(::RLWE, K::RLWEPrivKey, M::Array{UInt8, 1}) #::Array{UInt8}
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
