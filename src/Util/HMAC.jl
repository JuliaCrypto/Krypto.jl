# HMAC protocol implementation in Julia
# Copyright (C): Jaka Smrekar (vinctux) <vinctux@outlook.com>, 2016

using Krypto
using SHA

function HMAC{S<:SHA.SHA_CTX}(K::Array{UInt8, 1}, M::Array{UInt8, 1}, H::S)
    if length(K) > B K = H(K) end
    if length(K) < B K = vcat(K, [0o00 for i in 1:(B - length(K))]) end
    O = xor([0o134 for i in 1:B], K)
    I = xor([0o66  for i in 1:B], K)
    return H(vcat(O, H(vcat(I, M))))
end
