# Lattice math utils implementation in Julia
# Copyright (C): Jaka Smrekar (vinctux) <vinctux@outlook.com>, 2016
#
# Reference:       https://eprint.iacr.org/2014/725.pdf
#                  https://eprint.iacr.org/2015/138.pdf
#                  https://eprint.iacr.org/2016/049.pdf
#                  https://securewww.esat.kuleuven.be/cosic/publications/article-2444.pdf
# x86 C reference: https://github.com/ruandc/Ring-LWE-Encryption/blob/master/x86

using Krypto
using Primes
using Polynomials

# Find the primitive root
function primroot(n::Integer) #::Integer
    if n < 2 return 1 end
    while true
        R = rand(RandomDevice(), 2:n)
        c = false
        for F in factor(n - 1)
            if c break end
            if powermod(R, div(n - 1, F[1]), n) == 1 c = true end
        end
        if !c return R end
    end
end

# Uniformly sample from [-B:B] a polynomial in ring
function UniformSample(B::Integer, L::Integer, q::Integer)
    if B < 0 error("Bound limit cannot be negative.")
    elseif B > 2^16 - 1 || B == 0 warn("Bound limit is set to the highest or lowest possible point. Expect errors."); return Poly([0]) end
    E = Array{Int16, 1}()
    for i in 1:L append!(E, rand((-B):B) % q) end
    return Poly(E)
end

# Forward Number Theoretic Transform, with mod q
function NTT(a::Poly, q::Integer) #::Poly
    A, m = a, 1
    for m in 2:(2m):div(degree(a), 2)
        ψ = primroot(m)
        ω = Int64(round(sqrt(ψ)))
        for j in 0:2:m
            for k in 0:(2m):degree(A)
                u1 = A[j + k];
                t1 = (ω * A[j + k + 1]) % q
                u2 = A[j + k + m];
                t2 = (ω * A[j + k + m + 1]) % q

                A[j + k] = (u1 + t1) % q
                A[j + k + 1] = (u2 + t2) % q
                A[j + k + m] = (u1 - t1) % q
                A[j + k + m + 1] = (u2 - t2) % q
            end
            ω = (ω * ψ) % q
        end
    end

    ψ = 5118
    ω = 1065
    for j in 0:div(degree(a), 2)
        t1 = (ω * A[2j + 1]) % q
        u1 = A[2j] % q
        A[2j] = (u1 + t1) % q
        A[2j + 1] = (u1 - t1) % q
        ω = (ω * ψ) % q
    end
end

# Inverse NTT, with mod q
function INTT(a::Poly, q::Integer) #::Poly
    A, m = a, 1
    for m in 1:(2m):div(degree(a), 2)
        ψ = primroot(m)
        ω = 1
        for j in 0:div(m, 2)
            for k in 0:m:degree(a)
                t1 = (ω * A[2(k + j) + 1]) % q
                u1 = A[2(k + j)]
                t2 = (ω * A[2 * (k + j + m / 2) + 1]) % q
                u2 = A[2(k + j) + m]

                A[2(k + j)] = (u1 + t1) % q
                A[2(k + j) + m] = (u1 - t1) % q
                A[2(k + j) + 1] = (u2 + t2) % q
                A[2(k + j) + m + 1] = (u2 - t2) % q
            end
            ω = (ω * ψ) % q
        end
    end

    ψ = 2880
    ω = 1
    for j in 0:2:degree(a)
        u = a[j]
        t = (ω * a[j + 1]) % q
        a[j] = (u + t) % q
        a[j + 1] = (u - t) % q
        ω = (ω * ψ) % q
    end

    ω_2 = UInt32(3383)
    ψ = 2481
    ν = 7651  # Scaling
    ω = 1
    for j in 0:degree(a)
        if iseven(j) a[j] = (a[j] * ων) % q; ω = (ω * ψ) % q
        else a[j] = (a[j] * ω_2 * ν) % q; ω_2 = (ω_2 * ψ) % q end
    end
end

# Generate a polynomial A in ring (only for testing)
function GenerateA(L::Integer, q::Integer, nttbool::Bool = false) #::Poly
    A = Array{Int64, 1}()
    for i in 1:div(L, 2)
        r = rand(RandomDevice(), UInt16)
        append!(A, (r & 0xffff) % q)
        append!(A, (r >> 16) % q)
    end
    return nttbool ? NTT(Poly(A), q) : Poly(A)
end

# Generate a polynomial R2 in ring
function GenerateR2(L::Integer, q::Integer, nttbool::Bool = false) #::Poly
    R2 = Array{Int64, 1}()
    while length(R2) < L
        r = rand(RandomDevice(), UInt16)
        for j in 1:16
            B = r & 1
            S = (r >> 1) & 1
            if S & B == 1 B = q - 1 end
            append!(R2, B)
            r >>= 2
        end
    end
    return nttbool ? NTT(Poly(R2), q) : Poly(R2)
end

# Trivially encode an octet array into a message polynomial
function bytes2poly(M::Array{UInt8, 1}) #::Poly
    O = Array{Int64, 1}()
    for i in 1:length(M) append!(O, M[i]) end
    return Poly(O)
end

# Trivially decode a message polynomial into an octet array
function poly2bytes(M::Poly) #::Aray{UInt8, 1}
    O = Array{UInt8, 1}()
    for i in 1:degree(M) append!(O, M[i]) end
    return O
end
