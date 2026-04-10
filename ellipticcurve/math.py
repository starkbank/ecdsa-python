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
    def multiplyAndAdd(cls, p1, n1, p2, n2, N, A, P):
        """
        Compute n1*p1 + n2*p2 using Shamir's trick (simultaneous double-and-add).
        Not constant-time — use only with public scalars (e.g. verification).

        :param p1: First point
        :param n1: First scalar
        :param p2: Second point
        :param n2: Second scalar
        :param N: Order of the elliptic curve
        :param A: Coefficient of the first-order term of the equation Y^2 = X^3 + A*X + B (mod p)
        :param P: Prime number in the module of the equation Y^2 = X^3 + A*X + B (mod p)
        :return: Point n1*p1 + n2*p2
        """
        return cls._fromJacobian(
            cls._shamirMultiply(
                cls._toJacobian(p1), n1,
                cls._toJacobian(p2), n2,
                N, A, P,
            ), P,
        )

    @classmethod
    def inv(cls, x, n):
        """
        Modular inverse using Fermat's little theorem: x^(n-2) mod n.
        Requires n to be prime (true for all ECDSA curve parameters).
        Uses Python's built-in pow() which has more uniform execution time
        than the extended Euclidean algorithm.

        :param x: Divisor
        :param n: Mod for division (must be prime)
        :return: Value representing the division
        """
        if x == 0:
            return 0

        return pow(x, n - 2, n)

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

        qz2 = (qz * qz) % P
        pz2 = (pz * pz) % P
        U1 = (px * qz2) % P
        U2 = (qx * pz2) % P
        S1 = (py * qz2 * qz) % P
        S2 = (qy * pz2 * pz) % P

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
        nz = (H * pz * qz) % P

        return Point(nx, ny, nz)

    @classmethod
    def _jacobianMultiply(cls, p, n, N, A, P):
        """
        Multiply point and scalar in elliptic curves using Montgomery ladder
        for constant-time execution.

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
        Compute n1*p1 + n2*p2 using Shamir's trick (simultaneous double-and-add).
        Not constant-time — use only with public scalars (e.g. verification).

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

        jp1p2 = cls._jacobianAdd(jp1, jp2, A, P)

        _add = cls._jacobianAdd
        _double = cls._jacobianDouble

        l = max(n1.bit_length(), n2.bit_length())
        r = Point(0, 0, 1)

        for i in range(l - 1, -1, -1):
            r = _double(r, A, P)
            b1 = (n1 >> i) & 1
            b2 = (n2 >> i) & 1
            if b1:
                r = _add(r, jp1p2 if b2 else jp1, A, P)
            elif b2:
                r = _add(r, jp2, A, P)

        return r
