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
        if p.y == 0:
            return Point(0, 0, 0)

        ysq = (p.y ** 2) % P
        S = (4 * p.x * ysq) % P
        M = (3 * p.x ** 2 + A * p.z ** 4) % P
        nx = (M**2 - 2 * S) % P
        ny = (M * (S - nx) - 8 * ysq ** 2) % P
        nz = (2 * p.y * p.z) % P

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

        U1 = (p.x * q.z ** 2) % P
        U2 = (q.x * p.z ** 2) % P
        S1 = (p.y * q.z ** 3) % P
        S2 = (q.y * p.z ** 3) % P

        if U1 == U2:
            if S1 != S2:
                return Point(0, 0, 1)
            return cls._jacobianDouble(p, A, P)

        H = U2 - U1
        R = S2 - S1
        H2 = (H * H) % P
        H3 = (H * H2) % P
        U1H2 = (U1 * H2) % P
        nx = (R ** 2 - H3 - 2 * U1H2) % P
        ny = (R * (U1H2 - nx) - S1 * H3) % P
        nz = (H * p.z * q.z) % P

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
