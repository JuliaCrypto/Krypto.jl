# ECC protocol implementation in Julia
# Copyright (C): Jaka Smrekar (vinctux) <vinctux@outlook.com>, 2016
#
# PyECC (https://github.com/amintos/PyECC) as Pythonic reference

importall Base
using Krypto

abstract ECCKey

type ECCPubKey <: ECCKey
end

type ECCPrivKey <: ECCKey
end
