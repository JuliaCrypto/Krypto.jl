# Lattice math utils implementation in Julia
# Copyright (C): Jaka Smrekar (vinctux) <vinctux@outlook.com>, 2016
#
# References:      [1]  https://eprint.iacr.org/2014/725.pdf
#                           Ruan de Clercq et al., 2014
#                           Efficient Software Implementation of Ring-LWE Encryption
#                  [2]  https://eprint.iacr.org/2015/138.pdf
#                           Vikram Singh, 2015
#                           A Practical Key Exchange for the Internet using Lattice Cryptography
#                  [3]  https://eprint.iacr.org/2016/049.pdf
#                           Christoph M. Mayer, 2016
#                           Implementing a Toolkit for Ring-LWE Based Cryptography
#                                            in Arbitrary Cyclotomic Number Fields
#                  [4]  https://securewww.esat.kuleuven.be/cosic/publications/article-2444.pdf
#                           Sujoy Sinha Roy et al., 2014
#                           Compact Ring-LWE Cryptoprocessor
#                  [5]  https://www.microsoft.com/en-us/research/wp-content/uploads/2016/05/RLWE-1.pdf
#                           Patrick Longa and Michael Naehrig, 2016
#                           Speeding up the Number Theoretic Transform
#                           for Faster Ideal Lattice-Based Cryptography
#                  [6]  http://web.maths.unsw.edu.au/~davidharvey/papers/fastntt/
#                           David Harvey, 2013
#                           Faster arithmetic for number-theoretic transforms
# x86 C reference: [C1] https://github.com/ruandc/Ring-LWE-Encryption/blob/master/x86
#                  [C2] https://github.com/dconnolly/msr-latticecrypto/blob/master/generic/ntt.c
#                  [C3] https://github.com/open-quantum-safe/liboqs/tree/master/src/kex_rlwe_bcns15

using Krypto
using Polynomials

abstract Moduli
type LatticeModuli <: Moduli
    k::Integer
    m::Integer
    l::Integer
end

# K-RED reduction function [5:p7]
function KRED(C::Integer, Q::LatticeModuli)
    M = 2^Q.m
    C0 = C % M
    C1 = div(C, M)
    return Q.k * C0 - C1
end

# K-RED-2X reduction function [5:p7]
function KRED2(C::Integer, Q::LatticeModuli)
    M = 2^Q.m
    C0 = C % M
    C1 = div(C, M) % M
    C2 = div(C, M << Q.m)
    return Q.k * C0 - C1 + C2
end

# Optimized Forward NTT-CT with K-RED reduction [5:p9]
# FIXME: NTTK currently not working. It's trying to access A @ 1537, bound is 1025, although it should be 1024.
#        Currently set k = n >> 2 (for testing the heuristic), should be k = n.
function NTTK(a::Poly, Q::LatticeModuli, n::Integer)
    A, k, N = a.a, n >> 2, 1
    for m in vcat([1], [N <<= 1 for _ in 1:(ndigits(n, 2) - 2)])
        k >>= 1
        for i in 0:m
            jx = 2 * i * k + 1
            S = Ψ[n][m + i]
            for j in jx:(jx + k - 1)
                U = A[j]
                V = A[j + k] * S
                if m == 128
                    U = KRED(U, Q)
                    V = KRED2(V, Q)
                else
                    V = KRED(V, Q)
                end
                A[j] = U + V
                A[j + k] = U - V
            end
        end
    end
    return Poly(A)
end

# Optimized INTT-GS with K-RED reduction [5:p10]
function INTTK(a::Poly, Q::LatticeModuli, n::Integer)
    A, k, N = rev(a.a), 1, n << 1
    for m in [N >>= 1 for _ in 1:(ndigits(N, 2) - 2)]
        j1 = 2
        h = m >> 1
        for i in 0:h
            j2 = j1 + k - 1
            S = Ψ_[n][h + i]
            for j in j1:j2
                U = A[j]
                V = A[j + k]
                if m == 32
                    A[j] = KRED(a[j], Q)
                    A[j + k] = KRED2(a[j + k], Q)
                else
                    A[j + k] = KRED(a[j + k], Q)
                end
            end
            j1 += 2k
        end
        k <<= 1
    end
    for j in 1:(k + 1)
        U = a[j]
        V = a[j + k]
        A[j] = KRED((U + V) * rev(rev(n) * rev(k^11)), Q)
        A[j + k] = KRED((U - V) * rev(rev(n) * rev(k^10) * Ψ_[n][1]), Q)
    end
    return Poly(A)
end

# Uniformly sample from [-B:B] a polynomial in ring
function UniformSample(B::Integer, N::Integer)
    if B < 0 error("Bound limit cannot be negative.")
    elseif B > 2^16 - 1 || B == 0 warn("Bound limit is set to the highest or lowest possible point. Expect errors."); return Poly([0]) end
    E = Array{Int64, 1}()
    for i in 0:N append!(E, randbit(B)) end
    return Poly(E)
end

# Generate a polynomial A in ring
function GenerateA{T<:Integer}(L::T, nttbool::Bool = false)
    A, R = Array{Int64, 1}(), RandomDevice()
    for i in 0:div(L, 2)
        r = rand(R, UInt16)
        append!(A, (r & 0xffff) % 12289)
        append!(A, (r >> 16) % 12289)
    end
    return nttbool ? NTTK(Poly(A), 12289) : Poly(A)
end

# Generate a polynomial R2 in ring
function GenerateR2{T<:Integer}(L::T, nttbool::Bool = false)
    R2, R = Array{Int64, 1}(), RandomDevice()
    while length(R2) < L
        r = rand(R, UInt16)
        for j in 1:16
            B, S = r & 1, (r >> 1) & 1
            if S & B == 1 B = 12288 end
            append!(R2, B)
            r >>= 1
        end
    end
    return nttbool ? NTTK(Poly(R2), 12289) : Poly(R2)
end

# Trivially compression encode an octet array into a message polynomial
#  => compress 8 bytes into a 1 coefficient (64-bit).
# FIXME: Currently input MUST be length power of 2.
# FIXME: Doesn't seems to correctly handle compression... Redir to B2P() for now.
function bytes2poly(M::Array{UInt8, 1})
    return B2P(M)   # Only temporary
    O, B = Array{Int64, 1}(), "0b"
    for i in 1:length(M)
        if i % 8 == 1 && i > 1
            N = false
            assert(length(B) == 66)
            if B[3] == '1'
                B = "0b" * B[4:end]
                N = true
            end
            append!(O, parse(Int64, B) * (N ? -1 : 1))
            B = "0b"
        end
        B *= bits(M[i])
    end
    return Poly(O)
end
B2P(M::Array{UInt8, 1}) = Poly(Array{Int64, 1}(M))  # Ineffective for MEM but works.

# Trivially compression decode a message polynomial into an octet array
#  => decompress 1 coefficient into 8 bytes.
# FIXME: Returns empty Array{UInt8, 1}(). Redir to P2B() for now.
function poly2bytes(P::Poly{Int64})
    return P2B(P)
    O, M = Array{UInt8, 1}(), P.a
    for i in 1:length(M)
        X = abs(M[i])
        I = [UInt8((X & 0x00000000000000ff)), #+ (M[i] < 0 ? 0x1000000000000000 : 0x0)),
             UInt8((X & 0x000000000000ff00) >> 8),
             UInt8((X & 0x0000000000ff0000) >> 16),
             UInt8((X & 0x00000000ff000000) >> 24),
             UInt8((X & 0x000000ff00000000) >> 32),
             UInt8((X & 0x0000ff0000000000) >> 40),
             UInt8((X & 0x00ff000000000000) >> 48),
             UInt8((X & 0xff00000000000000) >> 56)]
        vcat(O, I)
    end
    return O
end
P2B(P::Poly{Int64}) = Array{UInt8, 1}(P.a)  # Ineffective for MEM but works.
