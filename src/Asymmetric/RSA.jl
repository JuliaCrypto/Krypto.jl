# RSA protocol (RFC-3447) implementation in Julia
# Copyright (C): Jaka Smrekar (vinctux) <vinctux@outlook.com>, 2016
#
# PyCrypto (https://github.com/dlitz/pycrypto) as Pythonic reference

using Krypto
using SHA

abstract RSAKey

type RSAPubKey <: RSAKey
    n::BigInt             # RSA modulus
    e::BigInt             # RSA public component
    o::Array{UInt8, 1}    # Octet array representation of RSA key (n, e)
    hex::AbstractString   # Hex representation of RSA key (n, e)
end
RSAPubKey() = RSAPubKey(0, 65537, Array{UInt8, 1}(), "")

type RSAPrivKey <: RSAKey
    n::BigInt             # RSA modulus
    d::BigInt             # RSA private component
    o::Array{UInt8, 1}    # Octet array representation of RSA key (n, e)
    hex::AbstractString   # Hex representation of RSA key (n, e)
end
RSAPrivKey() = RSAPrivKey(0, 65537, Array{UInt8, 1}(), "")

# RFC-3447/4.1
function IP2OS{T<:Integer, L<:Integer}(x::T, xLen::L)
    #if x >= 256^BigInt(xLen) error("Integer too large.") end
    X = Array{UInt8, 1}()
    while x > 256 append!(X, x % 256); x = div(x, 256) end
    while length(X) < xLen append!(X, 0o0) end
    return reverse(X)
end
IP2OS{T<:Integer}(x::T) = IP2OS(x, div(bitsize(x), 8))

# RFC-3447/4.2
function OS2IP(X::Array{UInt8, 1})
    x = BigInt(0)
    for i in 1:length(X) x += X[i] * 256^BigInt(length(X) - i) end
    return x
end

function OS2STR(X::Array{UInt8, 1})
    r = ""
    for i in 1:length(X) r *= string(Char('\0' + d)) end
    return r
end

# RFC-3447/5.1.1
function RSAEP(pubkey::RSAPubKey, m::Integer)
    if m > pubkey.n - 1 || m < 0 error("Message representative out of range.") end
    return powermod(m, pubkey.e, pubkey.n)
end

# RFC-3447/5.1.2
function RSADP(privkey::RSAPrivKey, m::Integer)
    if m > privkey.n - 1 || m < 0 error("Message representative out of range.") end
    return powermod(m, privkey.d, privkey.n)
end

# RFC-3447/5.2.1
function RSASP1(privkey::RSAPrivKey, m::Integer)
    if m > privkey.n - 1 || m < 0 error("Message representative out of range.") end
    return powermod(m, privkey.d, privkey.n)
end

# RFC-3447/5.2.2
function RSAVP1(pubkey::RSAPubKey, m::Integer)
    if m > pubkey.n - 1 || m < 0 error("Signature representative out of range.") end
    return powermod(m, pubkey.e, pubkey.n)
end

# FIXME: RSAES_PKCS1_V1_5_ENCRYPT not working properly.
# RFC-3447/7.2.1
function RSAES_PKCS1_V1_5_ENCRYPT(pubkey::RSAPubKey, M::Array{UInt8, 1})
    k, mLen = length(IP2OS(pubkey.n)), length(M)
    mLen > k - 11 && error("Message too long.")
    PS = [csrand(0o1:0o255) for i in 1:(k - mLen - 3)]
    EM = vcat([0o0, 0o2], PS, [0o0], M)
    m, c, C = OS2IP(EM), RSAEP(pubkey, m), IP2OS(c, k)
    return C
end

# FIXME: RSAES_PKCS1_V1_5_DECRYPT not working properly.
# RFC-3447/7.2.2
function RSAES_PKCS1_V1_5_DECRYPT(privkey::RSAPrivKey, C::Array{UInt8, 1})
    k = length(IP2OS(privkey.n))
    length(C) != k && error("Decryption error.")
    EM = IP2OS(RSADP(privkey, OS2IP(C)), k)
    (EM[1] != 0o0 || EM[2] != 0o2) && error("Decryption error.")
    i, PS = 3, Array{UInt8, 1}()
    while EM[i] != 0o0 vcat(PS, EM[i]); i += 1 end
    i < 8 && error("Decryption error.")
    M = EM[(i + 1):end]
    return M
end

# FIXME: RSASSA_PKCS1_V1_5_SIGN not working properly.
# RFC-3447/8.2.1
function RSASSA_PKCS1_V1_5_SIGN(privkey::RSAPrivKey, M::Array{UInt8, 1})
    EM = EMSA_PKCS1_V1_5_ENCODE(M, length(IP2OS(privkey.n)))
    return IP2OS(RSASP1(privkey, OS2IP(EM)))
end

# FIXME: RSASSA_PKCS1_V1_5_VERIFY not working properly.
# RFC-3447/8.2.2
function RSASSA_PKCS1_V1_5_VERIFY(pubkey::RSAPubKey, M::Array{UInt8, 1}, S::Array{UInt8, 1})
    k = length(IP2OS(pubkey.n))
    length(S) != k && error("Invalid signature.")
    EM1, EM2 = IP2OS(RSAVP1(pubkey, OS2IP(S)), k), EMSA_PKCS1_V1_5_ENCODE(M, k)
    return EM1 == EM2
end

# TODO: Use DER/BER encoding standard before concating.
# RFC-3447/9.1
EMSA_PKCS1_V1_5_ENCODE{C<:SHA.SHA_CTX}(M::Array{UInt8, 1}, k::Integer, H::C = SHA.SHA3_CTX) =
    vcat([0o0, 0o1], [0o377 for i in 1:(k - length(M) - 3)], [0o0], update!(H, M))

function RSAKeyGen{T<:Integer}(b::T, e::T = 65537, newe::Bool = false, ERR::Int8 = Int8(75))
    if (b - 1024) % 256 != 0 error("Number of bits should be in form b = 1024 + 256x.") end
    p = q = BigInt(1)
    while bitsize(BigInt(p * q)) < b
        p = BigInt(csprime(div(b, 2), ERR))
        q = BigInt(csprime(div(b, 2), ERR))
    end
    N = BigInt(p * q)
    phi = BigInt(N - (p + q - 1))
    if newe
        e = BigInt(csrand(1:phi))
        while gcd(e, phi) != 1 e = csrand(1:phi) end
    end
    PUB  = RSAPubKey(N, e, Array{UInt8, 1}(), "")
    PRIV = RSAPrivKey(N, invmod(e, phi), Array{UInt8, 1}(), "")
    return PUB, PRIV
end


## SHORTHANDS ##
RSAEncrypt(pubkey::RSAPubKey,   M::Array{UInt8, 1}) = RSAES_PKCS1_V1_5_ENCRYPT(pubkey, M)
RSADecrypt(privkey::RSAPrivKey, C::Array{UInt8, 1}) = RSAES_PKCS1_V1_5_DECRYPT(privkey, C)
RSASign(privkey::RSAPrivKey,    M::Array{UInt8, 1}) = RSASSA_PKCS1_V1_5_SIGN(privkey, M)
RSAVerify(pubkey::RSAPubKey,    M::Array{UInt8, 1}, S::Array{UInt8, 1}) = RSASSA_PKCS1_V1_5_VERIFY(pubkey, M, S)

encrypt(::Type{Krypto.RSA}, K::RSAPubKey,  M::Array{UInt8, 1}) = RSAEncrypt(K, M)
decrypt(::Type{Krypto.RSA}, K::RSAPrivKey, C::Array{UInt8, 1}) = RSADecrypt(K, C)
sign(::Type{Krypto.RSA},    K::RSAPrivKey, M::Array{UInt8, 1}) = RSASign(K, M)
verify(::Type{Krypto.RSA},  K::RSAPubKey,  C::Array{UInt8, 1}) = RSAVerify(K, C)
