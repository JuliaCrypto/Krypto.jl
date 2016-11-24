# Salsa20 implementation in Julia
# Copyright (C): Jaka Smrekar (vinctux) <vinctux@outlook.com>, 2016
#
# Reference:       https://cr.yp.to/snuffle/salsafamily-20071225.pdf
# x86 C reference: https://cr.yp.to/snuffle/salsa20/ref/salsa20.c
#                  https://github.com/keybase/python-salsa20/blob/master/libsodium-salsa20

using Krypto

global const σ = Array{UInt8, 1}("expand 32-byte k")

function LLE(x::Array{UInt8, 1}, l::Integer)
    a = 0
    for i in 0:3 a |= (Int32(x[l + i + 1]) << 8i) end
    return a
end
SLE(u::Int32) = [(u & [0x000000FF, 0x0000FF00, 0x00FF0000, 0xFF000000][i]) >> 8i for i in 1:4]

# Salsa20 cryptographic primitive
function SALSA20(I::Array{UInt8, 1}, k::Array{UInt8, 1}, c::Array{UInt8, 1}, R::Integer = 20)
    X = J = Int32[LLE(c, 0),  LLE(k, 0),  LLE(k, 4),  LLE(k, 8),
                  LLE(k, 12), LLE(c, 4),  LLE(I, 0),  LLE(I, 4),
                  LLE(I, 8),  LLE(I, 12), LLE(c, 8),  LLE(k, 16),
                  LLE(k, 20), LLE(k, 24), LLE(k, 28), LLE(c, 12)]
    for i in 1:2:R
        X[5]  ⊻= rotl( X[1] + X[13],  7)
        X[9]  ⊻= rotl( X[5] +  X[1],  9)
        X[13] ⊻= rotl( X[9] +  X[5], 13)
        X[1]  ⊻= rotl(X[13] +  X[9], 18)
        X[10] ⊻= rotl( X[6] +  X[2],  7)
        X[14] ⊻= rotl(X[10] +  X[6],  9)
        X[2]  ⊻= rotl(X[14] + X[10], 13)
        X[6]  ⊻= rotl( X[2] + X[14], 18)
        X[15] ⊻= rotl(X[11] +  X[7],  7)
        X[3]  ⊻= rotl(X[15] + X[11],  9)
        X[7]  ⊻= rotl( X[3] + X[15], 13)
        X[11] ⊻= rotl( X[7] +  X[3], 18)
        X[4]  ⊻= rotl(X[16] + X[12],  7)
        X[8]  ⊻= rotl( X[4] + X[16],  9)
        X[12] ⊻= rotl( X[8] +  X[4], 13)
        X[16] ⊻= rotl(X[12] +  X[8], 18)
        X[2]  ⊻= rotl( X[1] +  X[4],  7)
        X[3]  ⊻= rotl( X[2] +  X[1],  9)
        X[4]  ⊻= rotl( X[3] +  X[2], 13)
        X[1]  ⊻= rotl( X[4] +  X[3], 18)
        X[7]  ⊻= rotl( X[6] +  X[5],  7)
        X[8]  ⊻= rotl( X[7] +  X[6],  9)
        X[5]  ⊻= rotl( X[8] +  X[7], 13)
        X[6]  ⊻= rotl( X[5] +  X[8], 18)
        X[12] ⊻= rotl(X[11] + X[10],  7)
        X[9]  ⊻= rotl(X[12] + X[11],  9)
        X[10] ⊻= rotl( X[9] + X[12], 13)
        X[11] ⊻= rotl(X[10] +  X[9], 18)
        X[13] ⊻= rotl(X[16] + X[15],  7)
        X[14] ⊻= rotl(X[13] + X[16],  9)
        X[15] ⊻= rotl(X[14] + X[13], 13)
        X[16] ⊻= rotl(X[15] + X[14], 18)
    end
    for i in 1:16 X[i] += J[i] end
    return flat([SLE(x) for x in X])
end

# Salsa20 stream expander primitive
function Salsa20Stream(l::Integer, n::Array{UInt8, 1}, k::Array{UInt8, 1}, R::Integer = 20)
    assert(l > 0); assert(length(n) >= 8); assert(length(k) >= 32)
    I, C, q = vcat(n[1:8], zeros(UInt8, 8)), zeros(UInt8, l), l % 64
    for i in 0:div(l, 64)
        C[(64i + 1):64(i + 1)], u = SALSA20(I, k, σ, R), 1
        for j in 9:16
            I[j] = (u += UInt8(I[j]))
            u >>= 8
        end
    end
    if q > 0 C[1:q] = SALSA20(I, k, σ, R)[1:q] end
    return C
end

# Salsa20 xored stream expander primitive
function Salsa20StreamXOR(m::Array{UInt8, 1}, l::Integer, n::Array{UInt8, 1}, k::Array{UInt8, 1}, R::Integer = 20)
    assert(l > 0); assert(length(n) >= 8); assert(length(k) >= 32)
    I, C, q = vcat(n[1:8], zeros(UInt8, 8)), zeros(UInt8, l), l % 64
    for i in 0:(div(l, 64) - 1)
        B, u, t = SALSA20(I, k, σ, R), 1, (64i + 1):64(i + 1)
        C[t] = m[t] ⊻ B
        for j in 9:16
            I[j] = (u += UInt8(I[j]))
            u >>= 8
        end
    end
    if q > 0 C[1:q] = m[1:q] ⊻ SALSA20(I, k, σ, R)[1:q] end
    return C
end

encrypt(::Type{Krypto.Salsa20}, M::Array{UInt8, 1},
        IV::Array{UInt8, 1}, K::Array{UInt8, 1},
        R::Integer = 20) = Salsa20StreamXOR(M, length(M), IV, K, R)
decrypt(::Type{Krypto.Salsa20}, C::Array{UInt8, 1},
        IV::Array{UInt8, 1}, K::Array{UInt8, 1},
        R::Integer = 20) = encrypt(Krypto.Salsa20, C, IV, K, R)
