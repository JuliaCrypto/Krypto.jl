# RLWE specific tests
# Copyright (C): Jaka Smrekar (vinctux) <vinctux@outlook.com>, 2016

using Krypto
using Base.Test

println("RLWE TESTS STARTED...")

# Test values - 1024 octets (random, 0x00, 0xFF, flip)
T = [[csrand(0o1:0o255) for i in 1:256],
     [0o0 for i in 1:256],
     [0o377 for i in 1:256],
     [i % 2 == 0 ? 0o0 : 0o1 for i in 1:256]]

Q = 12289   # default; 40961 not supported (LUTs needed)
N = 1024    # default, also [256, 512, 1024]
B = 12      # default, also [8, 16]
println("RLWE config: [$(Q)-$(N)-$(B)]")
print("Generating polynomial 'A' ...")
@time A = GenerateA(N)
print("Generating RLWE keypair ($(N)-bit) ...")
@time PUB, PRIV = RLWEKeyGen(A, N)

for i in 1:length(T)
    print("Running encryption test #$(i) ...")
    @time E = RLWEEncrypt(PUB, T[i])
    println("Encrypted: $(E[1])\n$(E[2])\n\n")
    @time D = RLWEDecrypt(PRIV, E)
    println("Decrypted: $(D)\n\n\n===================================\n\n\n")
    @test D == bytes2poly(T[i])
end

println("ALL RLWE TESTS PASSED.")
