# coding: utf-8
from .point import Point


class Math:

    @classmethod
    def modularSquareRoot(cls, value, prime):
        """Tonelli-Shanks algorithm for modular square root. Works for all odd primes."""
        if value == 0:
            return 0
        if prime == 2:
            return value % 2

        # Factor out powers of 2: prime - 1 = Q * 2^S
        Q = prime - 1
        S = 0
        while Q % 2 == 0:
            Q //= 2
            S += 1

        if S == 1:  # prime = 3 (mod 4)
            return pow(value, (prime + 1) // 4, prime)

        # Find a quadratic non-residue z
        z = 2
        while pow(z, (prime - 1) // 2, prime) != prime - 1:
            z += 1

        M = S
        c = pow(z, Q, prime)
        t = pow(value, Q, prime)
        R = pow(value, (Q + 1) // 2, prime)

        while True:
            if t == 1:
                return R

            # Find the least i such that t^(2^i) = 1 (mod prime)
            i = 1
            temp = (t * t) % prime
            while temp != 1:
                temp = (temp * temp) % prime
                i += 1

            b = pow(c, 1 << (M - i - 1), prime)
            M = i
            c = (b * b) % prime
            t = (t * c) % prime
            R = (R * b) % prime

    @classmethod
    def multiplyGenerator(cls, curve, n):
        """
        Fast scalar multiplication n*G using a precomputed affine table of
        powers-of-two multiples of G and the width-2 NAF of n. Every non-zero
        NAF digit triggers one mixed add and zero doublings, trading the ~256
        doublings of a windowed method for ~86 adds on average — a large net
        reduction in field multiplications for 256-bit scalars.

        :param curve: Elliptic curve with generator G
        :param n: Scalar multiplier
        :return: Point n*G
        """
        if n < 0 or n >= curve.N:
            n = n % curve.N
        if n == 0:
            return Point(0, 0, 0)

        table = cls._generatorPowersTable(curve)
        A, P = curve.A, curve.P
        _add = cls._jacobianAdd

        r = Point(0, 0, 1)
        i = 0
        k = n
        while k > 0:
            if k & 1:
                digit = 2 - (k & 3)  # -1 or +1
                k -= digit
                g = table[i]
                if digit == 1:
                    r = _add(r, g, A, P)
                else:
                    r = _add(r, Point(g.x, P - g.y, 1), A, P)
            k >>= 1
            i += 1
        return cls._fromJacobian(r, P)

    @classmethod
    def _generatorPowersTable(cls, curve):
        """
        Build [G, 2G, 4G, ..., 2^nBitLength * G] in affine (z=1) form, so each
        add in multiplyGenerator hits the mixed-add fast path.
        """
        cached = getattr(curve, "_generatorPowersTable_", None)
        if cached is not None:
            return cached
        A, P = curve.A, curve.P
        current = Point(curve.G.x, curve.G.y, 1)
        table = [current]
        # NAF of an nBitLength-bit scalar can be up to nBitLength+1 digits.
        for _ in range(curve.nBitLength):
            doubled = cls._jacobianDouble(current, A, P)
            if doubled.y == 0:
                current = doubled
            else:
                zInv = cls.inv(doubled.z, P)
                zInv2 = (zInv * zInv) % P
                zInv3 = (zInv2 * zInv) % P
                current = Point((doubled.x * zInv2) % P, (doubled.y * zInv3) % P, 1)
            table.append(current)
        curve._generatorPowersTable_ = table
        return table

    @classmethod
    def multiply(cls, p, n, N, A, P):
        """
        Fast way to multily point and scalar in elliptic curves

        :param p: First Point to mutiply
        :param n: Scalar to mutiply
        :param N: Order of the elliptic curve
        :param P: Prime number in the module of the equation Y^2 = X^3 + A*X + B (mod p)
        :param A: Coefficient of the first-order term of the equation Y^2 = X^3 + A*X + B (mod p)
        :return: Point that represents the sum of First and Second Point
        """
        return cls._fromJacobian(
            cls._jacobianMultiply(cls._toJacobian(p), n, N, A, P), P
        )

    @classmethod
    def add(cls, p, q, A, P):
        """
        Fast way to add two points in elliptic curves

        :param p: First Point you want to add
        :param q: Second Point you want to add
        :param P: Prime number in the module of the equation Y^2 = X^3 + A*X + B (mod p)
        :param A: Coefficient of the first-order term of the equation Y^2 = X^3 + A*X + B (mod p)
        :return: Point that represents the sum of First and Second Point
        """
        return cls._fromJacobian(
            cls._jacobianAdd(cls._toJacobian(p), cls._toJacobian(q), A, P), P,
        )

    @classmethod
    def multiplyAndAdd(cls, p1, n1, p2, n2, N=None, A=None, P=None, curve=None):
        """
        Compute n1*p1 + n2*p2. If ``curve`` is given and exposes ``glvParams``
        (e.g. secp256k1), uses the GLV endomorphism to split both scalars into
        ~128-bit halves and run a 4-scalar simultaneous multi-exponentiation.
        Otherwise falls back to Shamir's trick with JSF. Not constant-time —
        use only with public scalars (e.g. verification).

        :param p1: First point
        :param n1: First scalar
        :param p2: Second point
        :param n2: Second scalar
        :param N: Order of the elliptic curve (ignored when ``curve`` is given)
        :param A: Coefficient of the first-order term (ignored when ``curve`` is given)
        :param P: Prime defining the field (ignored when ``curve`` is given)
        :param curve: Optional curve object; enables GLV if ``curve.glvParams`` is set
        :return: Point n1*p1 + n2*p2
        """
        if curve is not None:
            N, A, P = curve.N, curve.A, curve.P
            if curve.glvParams is not None:
                return cls._glvMultiplyAndAdd(p1, n1, p2, n2, curve)
        return cls._fromJacobian(
            cls._shamirMultiply(
                cls._toJacobian(p1), n1,
                cls._toJacobian(p2), n2,
                N, A, P,
            ), P,
        )

    @classmethod
    def _glvMultiplyAndAdd(cls, p1, n1, p2, n2, curve):
        """
        Compute n1*p1 + n2*p2 using the GLV endomorphism. Splits each 256-bit
        scalar into two ~128-bit scalars via k ≡ k1 + k2·λ (mod N), then runs
        a 4-scalar simultaneous double-and-add over (p1, φ(p1), p2, φ(p2))
        with a 16-entry precomputed table of subset sums. Halves the loop
        length versus the plain Shamir path.
        """
        glv = curve.glvParams
        N, A, P = curve.N, curve.A, curve.P
        beta = glv["beta"]

        k1, k2 = cls._glvDecompose(n1 % N, glv, N)
        k3, k4 = cls._glvDecompose(n2 % N, glv, N)

        # Base points (affine, z=1) — φ((x,y)) = (β·x mod P, y).
        bases = [
            Point(p1.x, p1.y, 1),
            Point((beta * p1.x) % P, p1.y, 1),
            Point(p2.x, p2.y, 1),
            Point((beta * p2.x) % P, p2.y, 1),
        ]
        scalars = [k1, k2, k3, k4]
        for i in range(4):
            if scalars[i] < 0:
                scalars[i] = -scalars[i]
                bases[i] = Point(bases[i].x, P - bases[i].y, 1)

        # Precompute table[idx] = sum of bases[i] selected by bits of idx.
        _add = cls._jacobianAdd
        table = [Point(0, 0, 1)] * 16
        for idx in range(1, 16):
            low = idx & -idx
            i = low.bit_length() - 1
            table[idx] = _add(table[idx ^ low], bases[i], A, P)

        _double = cls._jacobianDouble
        maxLen = max(s.bit_length() for s in scalars)
        r = Point(0, 0, 1)
        s0, s1, s2, s3 = scalars
        for bit in range(maxLen - 1, -1, -1):
            r = _double(r, A, P)
            idx = ((s0 >> bit) & 1) | (((s1 >> bit) & 1) << 1) \
                | (((s2 >> bit) & 1) << 2) | (((s3 >> bit) & 1) << 3)
            if idx:
                r = _add(r, table[idx], A, P)

        return cls._fromJacobian(r, P)

    @staticmethod
    def _glvDecompose(k, glv, N):
        """
        Decompose k into (k1, k2) with k ≡ k1 + k2·λ (mod N) and
        |k1|, |k2| ~ √N. Babai rounding against the precomputed basis
        {(a1, b1), (a2, b2)}; k1 and k2 may be negative.
        """
        a1, b1, a2, b2 = glv["a1"], glv["b1"], glv["a2"], glv["b2"]
        halfN = N // 2
        c1 = (b2 * k + halfN) // N
        c2 = (-b1 * k + halfN) // N
        k1 = k - c1 * a1 - c2 * a2
        k2 = -c1 * b1 - c2 * b2
        return k1, k2

    @classmethod
    def inv(cls, x, n):
        """
        Modular inverse via the Extended Euclidean Algorithm. Implemented in
        pure Python for compatibility with Python 2.7+ and 3.x. CPython 3.8+
        users get a faster C-level implementation via ``pow(x, -1, n)`` that
        this falls back to when available.

        :param x: Divisor (must be coprime to n)
        :param n: Mod for division
        :return: Value representing the division
        :raises ValueError: when x is 0 mod n (no inverse exists)
        """
        if x % n == 0:
            raise ValueError("0 has no modular inverse")

        try:
            return pow(x, -1, n)
        except (TypeError, ValueError):
            pass

        lm, hm = 1, 0
        low, high = x % n, n
        while low > 1:
            r = high // low
            lm, hm = hm - lm * r, lm
            low, high = high - low * r, low
        return lm % n

    @classmethod
    def _toJacobian(cls, p):
        """
        Convert point to Jacobian coordinates

        :param p: First Point you want to add
        :return: Point in Jacobian coordinates
        """
        return Point(p.x, p.y, 1)

    @classmethod
    def _fromJacobian(cls, p, P):
        """
        Convert point back from Jacobian coordinates

        :param p: First Point you want to add
        :param P: Prime number in the module of the equation Y^2 = X^3 + A*X + B (mod p)
        :return: Point in default coordinates
        """
        if p.y == 0:
            return Point(0, 0, 0)

        z = cls.inv(p.z, P)
        x = (p.x * z ** 2) % P
        y = (p.y * z ** 3) % P

        return Point(x, y, 0)

    @classmethod
    def _jacobianDouble(cls, p, A, P):
        """
        Double a point in elliptic curves

        :param p: Point you want to double
        :param P: Prime number in the module of the equation Y^2 = X^3 + A*X + B (mod p)
        :param A: Coefficient of the first-order term of the equation Y^2 = X^3 + A*X + B (mod p)
        :return: Point that represents the sum of First and Second Point
        """
        py = p.y
        if py == 0:
            return Point(0, 0, 0)

        px, pz = p.x, p.z
        ysq = (py * py) % P
        S = (4 * px * ysq) % P
        pz2 = (pz * pz) % P
        if A == 0:
            M = (3 * px * px) % P
        elif A == -3 or A == P - 3:
            M = (3 * (px - pz2) * (px + pz2)) % P
        else:
            M = (3 * px * px + A * pz2 * pz2) % P
        nx = (M * M - 2 * S) % P
        ny = (M * (S - nx) - 8 * ysq * ysq) % P
        nz = (2 * py * pz) % P

        return Point(nx, ny, nz)

    @classmethod
    def _jacobianAdd(cls, p, q, A, P):
        """
        Add two points in elliptic curves

        :param p: First Point you want to add
        :param q: Second Point you want to add
        :param P: Prime number in the module of the equation Y^2 = X^3 + A*X + B (mod p)
        :param A: Coefficient of the first-order term of the equation Y^2 = X^3 + A*X + B (mod p)
        :return: Point that represents the sum of First and Second Point
        """
        if p.y == 0:
            return q
        if q.y == 0:
            return p

        px, py, pz = p.x, p.y, p.z
        qx, qy, qz = q.x, q.y, q.z

        pz2 = (pz * pz) % P
        U2 = (qx * pz2) % P
        S2 = (qy * pz2 * pz) % P

        if qz == 1:
            # Mixed affine+Jacobian add: qz²=qz³=1 saves four multiplications.
            U1 = px
            S1 = py
        else:
            qz2 = (qz * qz) % P
            U1 = (px * qz2) % P
            S1 = (py * qz2 * qz) % P

        if U1 == U2:
            if S1 != S2:
                return Point(0, 0, 1)
            return cls._jacobianDouble(p, A, P)

        H = U2 - U1
        R = S2 - S1
        H2 = (H * H) % P
        H3 = (H * H2) % P
        U1H2 = (U1 * H2) % P
        nx = (R * R - H3 - 2 * U1H2) % P
        ny = (R * (U1H2 - nx) - S1 * H3) % P
        nz = (H * pz) % P if qz == 1 else (H * pz * qz) % P

        return Point(nx, ny, nz)

    @classmethod
    def _jacobianMultiply(cls, p, n, N, A, P):
        """
        Multiply point and scalar in elliptic curves using a branch-balanced
        Montgomery ladder: each scalar bit triggers exactly one add and one
        double in swapped order, masking simple branch-timing leaks. Note:
        Python's bignum arithmetic is NOT constant-time per operation, so
        total execution time still leaks through bignum-op duration. True
        constant-time ECDSA is not achievable in pure Python.

        :param p: First Point to multiply
        :param n: Scalar to multiply
        :param N: Order of the elliptic curve
        :param P: Prime number in the module of the equation Y^2 = X^3 + A*X + B (mod p)
        :param A: Coefficient of the first-order term of the equation Y^2 = X^3 + A*X + B (mod p)
        :return: Point that represents the scalar multiplication
        """
        if p.y == 0 or n == 0:
            return Point(0, 0, 1)

        if n < 0 or n >= N:
            n = n % N

        if n == 0:
            return Point(0, 0, 1)

        _add = cls._jacobianAdd
        _double = cls._jacobianDouble

        # Montgomery ladder: always performs one add and one double per bit
        r0 = Point(0, 0, 1)
        r1 = Point(p.x, p.y, p.z)

        for i in range(n.bit_length() - 1, -1, -1):
            if (n >> i) & 1 == 0:
                r1 = _add(r0, r1, A, P)
                r0 = _double(r0, A, P)
            else:
                r0 = _add(r0, r1, A, P)
                r1 = _double(r1, A, P)

        return r0

    @classmethod
    def _shamirMultiply(cls, jp1, n1, jp2, n2, N, A, P):
        """
        Compute n1*p1 + n2*p2 using Shamir's trick with Joint Sparse Form
        (Solinas 2001). JSF picks signed digits in {-1, 0, 1} so at most ~l/2
        digit pairs are non-zero, versus ~3l/4 for the raw binary form. Not
        constant-time — use only with public scalars (e.g. verification).

        :param jp1: First point in Jacobian coordinates
        :param n1: First scalar
        :param jp2: Second point in Jacobian coordinates
        :param n2: Second scalar
        :param N: Order of the elliptic curve
        :param A: Coefficient of the first-order term of the equation Y^2 = X^3 + A*X + B (mod p)
        :param P: Prime number in the module of the equation Y^2 = X^3 + A*X + B (mod p)
        :return: Point n1*p1 + n2*p2 in Jacobian coordinates
        """
        if n1 < 0 or n1 >= N:
            n1 = n1 % N
        if n2 < 0 or n2 >= N:
            n2 = n2 % N

        if n1 == 0 and n2 == 0:
            return Point(0, 0, 1)

        _add = cls._jacobianAdd
        _double = cls._jacobianDouble

        def neg(pt):
            return Point(pt.x, 0 if pt.y == 0 else P - pt.y, pt.z)

        jp1p2 = _add(jp1, jp2, A, P)
        jp1mp2 = _add(jp1, neg(jp2), A, P)
        addTable = {
            (1, 0): jp1,
            (-1, 0): neg(jp1),
            (0, 1): jp2,
            (0, -1): neg(jp2),
            (1, 1): jp1p2,
            (-1, -1): neg(jp1p2),
            (1, -1): jp1mp2,
            (-1, 1): neg(jp1mp2),
        }

        digits = cls._jsfDigits(n1, n2)
        r = Point(0, 0, 1)
        for u0, u1 in digits:
            r = _double(r, A, P)
            if u0 or u1:
                r = _add(r, addTable[(u0, u1)], A, P)

        return r

    @staticmethod
    def _jsfDigits(k0, k1):
        """
        Joint Sparse Form of (k0, k1): list of signed-digit pairs (u0, u1) in
        {-1, 0, 1}, ordered MSB-first. At most one of any two consecutive pairs
        is non-zero, giving density ~1/2 instead of ~3/4 from raw binary.
        """
        digits = []
        d0 = 0
        d1 = 0
        while k0 + d0 != 0 or k1 + d1 != 0:
            a0 = k0 + d0
            a1 = k1 + d1
            if a0 & 1:
                u0 = 1 if (a0 & 3) == 1 else -1
                if (a0 & 7) in (3, 5) and (a1 & 3) == 2:
                    u0 = -u0
            else:
                u0 = 0
            if a1 & 1:
                u1 = 1 if (a1 & 3) == 1 else -1
                if (a1 & 7) in (3, 5) and (a0 & 3) == 2:
                    u1 = -u1
            else:
                u1 = 0
            digits.append((u0, u1))
            if 2 * d0 == 1 + u0:
                d0 = 1 - d0
            if 2 * d1 == 1 + u1:
                d1 = 1 - d1
            k0 >>= 1
            k1 >>= 1
        digits.reverse()
        return digits
