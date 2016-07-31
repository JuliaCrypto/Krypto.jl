# ECC protocol implementation in Julia
# Copyright (C): Jaka Smrekar (vinctux) <vinctux@outlook.com>, 2016
#
# PyECC (https://github.com/amintos/PyECC) as Pythonic reference

# TODO: Write comment-like documentation for existent code.

importall Base
using Krypto

abstract ECCKey

type ECCPubKey <: ECCKey
end

type ECCPrivKey <: ECCKey
end
