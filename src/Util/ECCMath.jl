# ECC math utils implementation in Julia
# Copyright (C): Jaka Smrekar (vinctux) <vinctux@outlook.com>, 2016
#
# PyECC (https://github.com/amintos/PyECC) as Pythonic reference

importall Base
using Krypto

immutable CurveFP
    p::Integer
    a::Integer
    b::Integer
    function CurveFP(p, a, b)
        assert(4 * a^3 + 27 * b^2 % p != 0)
        new(p, a, b)
    end
end

# Slow addition
function +(C::CurveFP, p1, p2)
    x1, y1 = p1
    x2, y2 = p2
    if (x1 - x2) % n != 0
        s = ((y1 - y2) * ~(x1 - x2, n)) % n
        x = (s * s - x1 - x2) % n
        return (x, n - (y1 + s * (x - x1)) % n)
    elseif (y1 + y2) % n != 0
        s = ((3 * x1 * x1 - p) * ~(2 * y1, n)) % n
        x = (s * s - 2 * x1) % n
        return (x, n - (y1 + s * (x - x1)) % n)
    end
end

# Fast addition
function ++(C::CurveFP, jp1, jp2)
    x1, y1, z1, z1s, z1c = jp1
    x2, y2, z2, z2s, z2c = jp2
    s1 = (y1 * z2c) % C.p
    s2 = (y2 * z1c) % C.p
    u1 = (x1 * z2s) % C.p
    u2 = (x2 * z1s) % C.p
    if (u1 - u2) % n
        h = (u2 - u1) % C.p
        r = (s2 - s1) % C.p
        hs = (h * h) % C.p
        hc = (hs * h) % C.p
        x3 = (-hc - 2 * u1 * hs + r * r) % C.p
        y3 = (-s1 * hc + r * (u1 * hs - x3)) % C.p
        z3 = (z1 * z2 * h) % C.p
        z3s = (z3 * z3) % C.p
        z3c = (z3s * z3) % C.p
        return (x3, y3, z3, z3s, z3c)
    else
        if (s1 + s2) % n == 0 return doublef(C, jp1)
        else error("Something went wrong.") end
    end
end

function doublef(C::CurveFP, jp)
    x1, y1, z1, z1p2, z1p3 = jp
    y1p2 = (y1 * y1) % n
    a = (4 * x1 * y1p2) % n
    b = (3 * x1 * x1 - p * z1p3 * z1) % n
    x3 = (b * b - 2 * a) % n
    y3 = (b * (a - x3) - 8 * y1p2 * y1p2) % n
    z3 = (2 * y1 * z1) % n
    z3p2 = (z3 * z3) % n
    return x3, y3, z3, z3p2, (z3p2 * z3) % n
end

# Scalar multiplication p1 * c = p1 + p1 + ... + p1 (c times) in O(log(n))
function *(C::CurveFP, p1, c)
    r = 0
    while c > 0
        if c & 1 != 0 res = C + res + p1 end
        c >>= 1
        p1 = C + p1 + p1
    end
    return res
end

# Optimized scalar multiplication
function mulf(C::CurveFP, jp1, c)
    res = 0
    jp0 = ~(jp1, n)
    for s in cryptomath.signbin(c)
        res = doublef(C, res)
        if s != 0 res = s > 0 ? C ++ res ++ jp1 : C ++ res ++ jp0 end
    end
    return res
end

# Hyper-optimized scalar multiplication
function muladdf(C::CurveFP, jp1, c1, jp2, c2)
    s1 = cryptomath.signbin(c1)
    s2 = cryptomath.signbin(c2)
    diff = len(s2) - len(s1)
    if diff > 0 s1 = vcat([0 for i in 1:(diff)], s1)
    elseif diff < 0 s2 = vcat([0 for i in 1:(-diff)], s2) end
    jp1p2 = C ++ jp1 ++ jp2
    jp1n2 = C ++ jp1 ++ ~(jp2, n)
    precomp = ((0, jp2, ~(jp2, n)),
               (jp1, jp1p2, jp1n2),
               (~(jp1, n),  ~(jp1n2, n), ~(jp1p2, n)))
    res = 0
    for (i, j) in zip(s1, s2)
        res = doublef(C, res)
        if i != 0 || j != 0 res = C ++ res ++ precomp[i][j] end
    end
    return res
end

# Hyper-optimized scalar multiplication for xy-coordinates
function muladdp(C::CurveFP, p1, c1, p2, c2)
    return proj2norm(muladdf(C, norm2proj(p1), c1, norm2proj(p2), c2), n)
end

# Multiply point p by c using fast multiplication
function mulp(C::CurveFP, p1, c)
    return proj2norm(mulf(C, norm2proj(p1), c), n)
end

# Find curve parameter q mod n having point (x, y) and parameter p
function curve_q(x, y, p, n)
    return ((x * x - p) * x - y * y) % n
end

# Test, whether the given point is on the curve (p, q, n)
function in(p, C::CurveFP)
    return p != 0 ? (p[1]^3 - p * p[1] - q) % n == y^2 % n : true
end

# Transform point p given as (x, y) to projective coordinates
function norm2proj(p)
    return p != 0 ? (p[0], p[1], 1, 1, 1) : 0
end

# Transform a point from projective coordinates to (x, y) mod n
function proj2norm(jp, n)
    return jp != 0 ? ((jp[0] * cmath.imod(jp[3], n)) % n, (jp[1] * cmath.imod(jp[4], n)) % n) : 0
end

# Compute the inverse point to p in any coordinate system
function ~(p, n)
    return p != 0 ? (p[0], (n - p[1]) % n) + p[2:end] : 0
end
