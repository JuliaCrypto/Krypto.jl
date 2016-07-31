# RSA specific tests
# Copyright (C): Jaka Smrekar (vinctux) <vinctux@outlook.com>, 2016

using Krypto
using Base.Test

println("RSA TESTS STARTED...")

# Test values - 1024 octets (random, 0, 255, flip)
T = [[csrand(0o1:0o255) for i in 1:256],
     [0o0 for i in 1:256],
     [0o377 for i in 1:256],
     [i % 2 == 0 ? 0o0 : 0o1 for i in 1:256]]

# Key generation
# FIXME: Travis is erroring on keygen...
B = 4096
print("Generating $(B)-bit RSA keypair ... ")
@time PUB, PRIV = RSAKeyGen(B)
println("RSA Modulus n: $(hex(PUB.n))")
println("Private component d: $(hex(PRIV.d))")
println("Public component e: $(hex(PUB.e))")

# Encryption/decryption
#for t in T @test RSADecrypt(PRIV, RSAEncrypt(PUB, t)) == t end
for i in 1:length(T) print("Running encryption test #$(i) ..."); @time @test RSADP(PRIV, RSAEP(PUB, OS2IP(T[i]))) == OS2IP(T[i]) end

# Sign/verify
#for t in T @test RSAVerify(PUB, RSASign(PRIV, t), t) end
for i in 1:length(T) print("Running    signing test #$(i) ..."); @time @test RSAVP1(PUB, RSASP1(PRIV, OS2IP(T[i]))) == OS2IP(T[i]) end

println("ALL RSA TESTS PASSED.")
