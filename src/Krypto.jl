# KRYPTO.JL
module Krypto
using Compat
using SHA
using Primes
using Polynomials

########  Generic  ########
export encrypt, decrypt, sign, verify


########  Crypto types  ########
export CryptoAlgorithm, SymmetricCryptoAlgorithm, AsymmetricCryptoAlgorithm
export RSA, RLWE, ECC, NTRU
export AES, Blowfish, Twofish, Threefish, Serpent


########  RSA.jl  ########
export RSAKey, RSAPubKey, RSAPrivKey,                         # RSA Key Objects
       RSAKeyGen,                                             # RSA Key Generation Primitive
       RSAEP, RSADP, RSASP1, RSAVP1,                          # RSA Cryptographic Primitives
       RSAES_PKCS1_V1_5_ENCRYPT, RSAES_PKCS1_V1_5_DECRYPT,    # RSA Encryption Scheme PKCS v1.5 functions (encrypt)
       RSASSA_PKCS1_V1_5_SIGN, RSASSA_PKCS1_V1_5_VERIFY,      # RSA Encryption Scheme PKCS v1.5 functions (sign)
       OS2IP, IP2OS, OS2STR,                                  # Octet string convert functions
       RSAEncrypt, RSADecrypt, RSASign, RSAVerify             # RSA crypto function shorthands


########  ECC.jl  --  Elliptic-Curve Cryptography  ########
export ECCKey, ECCPubKey, ECCPrivKey                      # ECC Key objects


########  RLWE.jl  --  Ring Learning with Errors  ########
export RLWEKey, RLWEPubKey, RLWEPrivKey,                 # RLWE Key Objects
       RLWEKeyGen,                                       # RLWE Key Generation Primitive
       RLWEEncrypt, RLWEDecrypt                          # RLWE Cryptographic Primitives


########  CryptoMath.jl  ########
export bitsize, gpow,           # Determine bitsize of N; get first power of E, greater than N
       csrand, csrandbit,       # CSPRNG functions (via RandomDevice)
       e5,                      # Sieve of Atkin prime generation function
       csprime,                 # 'Strong' cryptographical prime generation function
       phi,                     # Euler's totient (phi) function
       gdb, signbin,            # Additional functions, required by ECC
       gprime, gprimemod        # Finds first prime 1) GEQ to N, 2) GEQ to N, while N % M == R


########  ECCMath.jl  ########
export CurveFP,                 # Curve object
       (+), (++), (*), (~),     # Scalar addition (+), fast addition (++), multiplication (*) and negation (~)
       mulf, doublef,           # Optimized (faster) scalar multiplication and doubling
       muladdf, muladdp,        # Hyper-optimized (fastest) scalar multiplication
       curve_q,                 # Find curve's Q % n, having point (x, y) and parameter p
       in,                      # Check if point lies on curve
       norm2proj, proj2norm     # Transfrom xy-coordinates into projective-coordinates, and vice versa


########  LatticeMath.jl  ########
export KRED, KRED2,              # Reduction functions (for NTT)
       UniformSample,            # Uniformly sample from [-B:B] an polynomial in ring
       NTTK, INTTK,              # Forward Number Theoretic Transform and its inverse
       GenerateA, GenerateR2,    # Generator functions for testing and crypto-deployment
       poly2bytes, bytes2poly    # Trivial en/decode of polynomials into/from octet arrays


########  HMAC.jl  ########
export HMAC               # Hash-based message authentication code


# Load files
include("LUT/rlwe.jl")
include("Util/CryptoTypes.jl")
include("Util/CryptoMath.jl")
include("Util/ECCMath.jl")
include("Util/LatticeMath.jl")
include("Util/HMAC.jl")
include("Asymmetric/RSA.jl")
include("Asymmetric/ECC.jl")
include("Asymmetric/RLWE.jl")

end # module Krypto
