# Various mathematical utils for cryptography processes.
# Copyright (C): Jaka Smrekar (vinctux) <vinctux@outlook.com>, 2016
#
# PyCrypto (https://github.com/dlitz/pycrypto) as Pythonic reference

using Primes
import Primes: isprime

# Get integer bitsize
function bitsize{T<:Integer}(N::T)
    b = BigInt(0)
    while N >> 1 > 0 b += 1 end
    return b
end

# Get first power of E, greater than N
function gpow(N::Integer, E::Integer = 2)
    if N <= 0 return 0 end
    x, I = N, 0
    while x <= N x *= E; I += 1 end
    return (x, I)
end

# Produce cryptographically-secure octet array of length b
function csrand{T<:Integer}(b::T)
    R = RandomDevice()
    O = Array{UInt8, 1}()
    for i in 1:b append!(O, rand(R, 0o0:0o255)) end
    return O
end
csrand{T<:Integer}(t::UnitRange{T}) = rand(RandomDevice(), t)

function csrandbit{T<:Integer}(b::T)
    O = "0b"
    for i in 1:b O *= csrand(0:1) == 0 ? "0" : "1" end
    return parse(BigInt, O)
end

# Sieve of Atkin - fast prime generator
# Author of this piece of code: @VicDrastik
# For reference:
#   - https://en.wikipedia.org/wiki/Sieve_of_Atkin
#   - https://github.com/JuliaLang/julia/issues/11594#issuecomment-109753437
function e5(s::BitArray{1})
    n = length(s)
    s[:] = false
    s[2] = true
    s[3] = true
    s[5:6:n] = true
    s[7:6:n] = true
    for p = 5:2:isqrt(n) if s[p] s[p*p:2p:n] = false end end
end

# Generates a strong prime, according to 10.1.1.17.2713
function csprime{T<:Integer}(b::T, ERR::Int8 = Int8(75))
    sieve_base = falses(10^8)
    e5(sieve_base)
    X = csrand((div(1414213562373095 * 2^BigInt(b - 1), 10^15)):2^BigInt(b) - 1)
    y1, y2 = csrandbit(101), csrandbit(101)
    P = Dict(y1 => BigInt(0), y2 => BigInt(0))
    F = falses(5 * length(sieve_base))
    _S = [BigInt(i) for i in 1:length(sieve_base) if sieve_base[i]]
    for y in [y1, y2]
        # TODO: Optimize with native zip - don't compute twice
        S = [(y % i, i) for i in 1:length(sieve_base) if sieve_base[i]]
        for i in 1:length(S) for j in (y + S[i][1] - S[i][2]):S[i][2]:length(F) F[j] = true end end
        for i in 1:length(F)
            if F[i] continue end
            t = y + i
            if isprime(t, ERR) P[y] = t; break end
        end
    end
    R = invmod(P[y2], P[y1]) * P[y2] - invmod(P[y1], P[y2]) * P[y1]
    Q = P[y1] * P[y2]
    Y0 = X + (R - (X % Q))
    while true
        pp = true
        for p in _S if Y0 % p == 0 pp = false; break end end
        if pp && isprime(Y0, ERR) break end
        Y0 += Q
    end
    return Y0
end
csprime(b::Integer) = csprime(b, Int8(75))

# Euler's totient function
# C++ reference:      https://gist.github.com/cslarsen/1635288
# Pythonic reference: https://stackoverflow.com/a/18114286/6489126
function phi{T<:Integer}(n::T, ERR::Int8 = Int8(75))
    if n < 0 n = -n end
    if n == 0 return 0
    elseif 0 < n <= 2 return 1 end
    if isprime(BigInt(n), ERR) return n - 1 end
    if n & 1 == 0 m = n >> 1; return ~(m & 1) == 0 ? phi(m) << 1 : phi(m) end
    O = 0
    for i in 1:n if gcd(n, i) == 1 O += 1 end end
    return O
end

# GDB function
# Pythonic reference: https://github.com/amintos/PyECC/blob/master/ecc/elliptic.py#L237-L244
function gdb{T<:Integer}(n::T)
    i = 1
    if n <= 0 return 0 end
    while n % i > 0 i <<= 1 end
    return i >> 2
end

# Transform n into a binary representation having signed bits.
# Pythonic reference: https://github.com/amintos/PyECC/blob/master/ecc/elliptic.py#L254-L271
function signbin{T<:Integer}(n::T)
    r = Array{Int8, 1}()
    while n > 1
        if n & 1 == 0
            cp = gbd(n + 1)
            cn = gbd(n - 1)
            if cp > cn append!(r, -1); n += 1
            else append!(r, 1); n -= 1 end
        else append!(r, 0) end
        n >>= 1
    end
    r.append(n)
    return reverse(r)
end

# Find first prime greater or equal to N
function gprime(N::Integer)
    if iseven(N) N += 1 end
    while !isprime(N, 75) N += 2 end
    return N
end

# Find first prime greater or equal to N, while also N % M == R
function gprimemod(N::Integer, M::Integer, R::Integer = 1)
    while N % M != R && !isprime(N, 75) N = gprime(N + 2) end
    return N
end
