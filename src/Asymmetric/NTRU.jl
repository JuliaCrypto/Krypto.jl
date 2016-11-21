# NTRU protocol implementation in Julia
# Copyright (C): Jaka Smrekar (vinctux) <vinctux@outlook.com>, 2016
#
# Reference: https://github.com/NTRUOpenSourceProject/ntru-crypto

importall Base
using Krypto

abstract NTRUKey

type NTRUPubKey <: NTRUKey
end

type NTRUPrivKey <: NTRUKey
end
