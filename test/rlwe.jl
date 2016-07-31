# RLWE specific tests
# Copyright (C): Jaka Smrekar (vinctux) <vinctux@outlook.com>, 2016

using Krypto
using Base.Test

println("RLWE TESTS STARTED...")

# Test values - 1024 octets (random, 0, 255, flip)
T = [[csrand(0o1:0o255) for i in 1:256],
     [0o0 for i in 1:256],
     [0o377 for i in 1:256],
     [i % 2 == 0 ? 0o0 : 0o1 for i in 1:256]]

Q = 40961
N = 1024
B = 16
println("RLWE config: [$(Q)-$(N)-$(B)]")
print("Generating polynomial 'A' ...")
@time A = GenerateA(N, Q)
print("Generating RLWE keypair ($(N)-bit) ...")
@time PUB, PRIV = RLWEKeyGen(A, Q, N)

for i in 1:length(T) print("Running encryption test #$(i) ..."); @time @test decrypt(RLWE, PRIV, encrypt(RLWE, PUB, T[i])) == T[i] end

println("ALL RLWE TESTS PASSED.")
