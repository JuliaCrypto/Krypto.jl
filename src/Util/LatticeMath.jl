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
#                  [7]  https://www.math.auckland.ac.nz/~sgal018/gen-gaussians.pdf
#                           Nagarjun C. Dwarakanath and Steven D. Galbraith, 2014
#                           Sampling from Discrete Gaussians for Lattice-based
#                                         Cryptography on a constrained Device
# x86 C reference: [C1] https://github.com/ruandc/Ring-LWE-Encryption/blob/master/x86
#                  [C2] https://github.com/dconnolly/msr-latticecrypto/blob/master/generic/ntt.c
#                  [C3] https://github.com/open-quantum-safe/liboqs/tree/master/src/kex_rlwe_bcns15

using Krypto

abstract Moduli
type LatticeModuli <: Moduli
    k::Int8
    m::Int8
    l::Int8
end
Int16(x::LatticeModuli) = Int16(x.k * 2^x.m + x.l)
Int(x::LatticeModuli) = Int16(x)

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
# FIXME: NTTK currently not working. It's trying to access A @ 1537, bound is 1025,
#        although it should be 1024.
function NTTK(A::Array{Int16, 1}, Q::LatticeModuli, n::Integer)
    k, N = n, 1
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
    return A
end

# Optimized INTT-GS with K-RED reduction [5:p10]
function INTTK(A::Array{Int16, 1}, Q::LatticeModuli, n::Integer)
    k, N = 1, n << 1
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
        U = A[j]
        V = A[j + k]
        A[j] = KRED((U + V) * rev(rev(n) * rev(k^11)), Q)
        A[j + k] = KRED((U - V) * rev(rev(n) * rev(k^10) * Ψ_[n][1]), Q)
    end
    return A
end

# Plain NTT-CT from [C1]
function NTT(A::Array{Int16, 1}, Q::LatticeModuli, n::Integer)
    i, q, N = 0, Int16(Q), 1
    for m in [N <<= 1 for _ in 1:(ndigits(n, 2) - 2)]
        ξ, ω = Ω[i += 1], Ω[i += 1]
        for j in 1:2:m
            for k in 0:2m:n
                u1 = A[j + k]
                t1 = (ω * A[j + k + 1]) % q

                u2 = A[j + k + m]
                t2 = (ω * A[j + k + m + 1]) % q

                A[j + k] = (u1 + t1) % q
                A[j + k + 1] = (u2 + t2) % q

                A[j + k + m] = (u1 - t1) % q
                A[j + k + m + 1] = (u2 - t2) % q
            end
            ω = ω * ξ % Int16(Q)
        end
    end

    ξ = 5118
    ω = 1065
    for j in 0:(div(n, 2) - 1)
        t1 = (ω * A[2 * j + 2]) % q
        u1 = A[2 * j + 1];
        A[2 * j + 1] = (u1 + t1) % q
        A[2 * j + 2] = (u1 - t1) % q
        ω = (ω * ξ) % q
    end
    return A
end

# Uniformly sample from [-B:B] a polynomial in ring
# FIXME: This should be Knuth-Yao.
function UniformSample(B::Int16, N::Integer)
    B < 0 && error("Bound limit cannot be negative.")
    E = Array{Int16, 1}()
    for i in 1:N append!(E, randbit(B)) end
    return E
end

# Element-wise multiplication of polynomials, in ring ZZ/Q
function *(x::Array{Int16, 1}, y::Array{Int16, 1}, Q::LatticeModuli)
    l = length(x)
    assert(l == length(y))
    return [(x[i] * y[i]) % Int16(Q) for i in 1:l]
end

# Element-wise addtion of polynomials, in ring ZZ/Q
function +(x::Array{Int16, 1}, y::Array{Int16, 1}, Q::LatticeModuli)
    l = length(x)
    assert(l == length(y))
    return [(x[i] + y[i]) % Int16(Q) for i in 1:l]
end

# Generate a CS-random polynomial of length L in ring ZZ/Q
function genrandpoly{T<:Integer}(L::T, Q::LatticeModuli; ntt_::Bool = false, N::Integer = 1024)
    A, R = Array{Int16, 1}(), RandomDevice()
    for i in 1:L append!(A, rand(R, Int16) % Int16(Q)) end
    return ntt_ ? NTTK(A, Q, N) : A
end
