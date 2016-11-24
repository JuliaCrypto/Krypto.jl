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

abstract RLWEKey

type RLWEPubKey <: RLWEKey
    A::Array{Int16, 1}
    P::Array{Int16, 1}
    N::Integer
    Q::LatticeModuli
end

type RLWEPrivKey <: RLWEKey
    R::Array{Int16, 1}
    N::Integer
    Q::LatticeModuli
end

global const B = Int16(12)                # Global sampling bound B
global const Q = LatticeModuli(3, 12, 1)  # Global moduli (== 12289)
global const QBY2 = div(Int16(Q), 2)
global const QBY4 = div(Int16(Q), 4)

# Generates RLWE keypair
function RLWEKeyGen(N::Integer = 1024)
    A = genrandpoly(N, Q)
    R1, R2 = UniformSample(B, N), genrandpoly(N, Q)
    P = R1 - *(A, R2, Q)
    PUB = RLWEPubKey(NTTK(A, Q, N), NTTK(P, Q, N), N, Q)
    PRIV = RLWEPrivKey(NTTK(R2, Q, N), N, Q)
    return PUB, PRIV
end

# RLWE Encryption primitive
function RLWEEncrypt(K::RLWEPubKey, M::Array{UInt8, 1})
    ERR = [UniformSample(B, K.N) for i in 1:3]
    E1, E2 = NTTK(ERR[1], K.Q, K.N), NTTK(ERR[2], K.Q, K.N)
    M16 = [Int16(x * QBY2) % Int16(Q) for x in M]
    C1 = +(*(K.A, E1, K.Q), E2, K.Q)
    C2 = +(*(K.P, E1, K.Q), NTTK(+(ERR[3], M16), K.Q, K.N), K.Q)
    return C1, C2
end

# RLWE Decryption primitive
RLWEDecrypt(K::RLWEPrivKey, C1::Array{Int32, 1}, C2::Array{UInt8, 1}) = INTTK(+(*(C1, K.R, K.Q), C2, K.Q), K.Q, K.N)
RLWEDecrypt(K::RLWEPrivKey, C::Tuple{Array{UInt8, 1}, Array{UInt8, 1}}) = RLWEDecrypt(K, C[1], C[2])

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
