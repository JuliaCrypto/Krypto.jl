# Salsa20 specific tests
# Copyright (C): Jaka Smrekar (vinctux) <vinctux@outlook.com>, 2016

using Krypto
using Base.Test

println("SALSA20 TESTS STARTED...")

# Test values - 1024 octets (random, 0x00, 0xFF, flip)
T = [[csrand(0o1:0o255) for i in 1:256],
     [0o0 for i in 1:256],
     [0o377 for i in 1:256],
     [i % 2 == 0 ? 0o0 : 0o1 for i in 1:256],
     Array{UInt8, 1}("This is Salsa20-Is this Salsa20?")]

IV = csrand(32)

for i in 1:length(T)
    for j in 1:length(T)
        println("Running encryption test #$(i) with key #$(j)... ")
        @time @test decrypt(Salsa20, encrypt(Salsa20, T[i], IV, T[j]), IV, T[j]) == T[i]
    end
end

println("ALL SALSA20 TESTS PASSED.")
