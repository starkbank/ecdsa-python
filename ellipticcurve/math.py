from binascii import hexlify


def multiply(a, n, N, A, P):
    """
    Fast way to multily point and scalar in elliptic curves

    :param (Xp,Yp,Zp): First Point to mutiply
    :param n: Scalar to mutiply
    :param N: Order of the elliptic curve
    :param P: Prime number in the module of the equation Y^2 = X^3 + A*X + B (mod p)
    :param A: Coefficient of the first-order term of the equation Y^2 = X^3 + A*X + B (mod p)
    :return: Point that represents the sum of First and Second Point
    """
    return fromJacobian(jacobianMultiply(toJacobian(a), n, N, A, P), P)


def add(a, b, A, P):
    """
    Fast way to add two points in elliptic curves

    :param a: First Point you want to add
    :param b: Second Point you want to add
    :param P: Prime number in the module of the equation Y^2 = X^3 + A*X + B (mod p)
    :param A: Coefficient of the first-order term of the equation Y^2 = X^3 + A*X + B (mod p)
    :return: Point that represents the sum of First and Second Point
    """
    return fromJacobian(jacobianAdd(toJacobian(a), toJacobian(b), A, P), P)


def inv(a, n):
    """
    Extended Euclidean Algorithm. It's the 'division' in elliptic curves

    :param a: Divisor
    :param n: Mod for division
    :return: Value representing the division
    """
    if a == 0:
        return 0
    lm, hm = 1, 0
    low, high = a % n, n
    while low > 1:
        r = high//low
        nm, new = hm-lm*r, high-low*r
        lm, low, hm, high = nm, new, lm, low
    return lm % n


def toJacobian((Xp, Yp)):
    """
    Convert point to Jacobian coordinates

    :param (Xp,Yp,Zp): First Point you want to add
    :return: Point in Jacobian coordinates
    """
    return (Xp, Yp, 1)


def fromJacobian((Xp, Yp, Zp), P):
    """
    Convert point back from Jacobian coordinates

    :param (Xp,Yp,Zp): First Point you want to add
    :param P: Prime number in the module of the equation Y^2 = X^3 + A*X + B (mod p)
    :return: Point in default coordinates
    """
    z = inv(Zp, P)
    return ((Xp * z**2) % P, (Yp * z**3) % P)


def jacobianDouble((Xp, Yp, Zp), A, P):
    """
    Double a point in elliptic curves

    :param (Xp,Yp,Zp): Point you want to double
    :param P: Prime number in the module of the equation Y^2 = X^3 + A*X + B (mod p)
    :param A: Coefficient of the first-order term of the equation Y^2 = X^3 + A*X + B (mod p)
    :return: Point that represents the sum of First and Second Point
    """
    if not Yp:
        return (0, 0, 0)
    ysq = (Yp ** 2) % P
    S = (4 * Xp * ysq) % P
    M = (3 * Xp ** 2 + A * Zp ** 4) % P
    nx = (M**2 - 2 * S) % P
    ny = (M * (S - nx) - 8 * ysq ** 2) % P
    nz = (2 * Yp * Zp) % P
    return (nx, ny, nz)


def jacobianAdd((Xp, Yp, Zp), (Xq, Yq, Zq), A, P):
    """
    Add two points in elliptic curves

    :param (Xp,Yp,Zp): First Point you want to add
    :param (Xq,Yq,Zq): Second Point you want to add
    :param P: Prime number in the module of the equation Y^2 = X^3 + A*X + B (mod p)
    :param A: Coefficient of the first-order term of the equation Y^2 = X^3 + A*X + B (mod p)
    :return: Point that represents the sum of First and Second Point
    """
    if not Yp:
        return (Xq, Yq, Zq)
    if not Yq:
        return (Xp, Yp, Zp)
    U1 = (Xp * Zq ** 2) % P
    U2 = (Xq * Zp ** 2) % P
    S1 = (Yp * Zq ** 3) % P
    S2 = (Yq * Zp ** 3) % P
    if U1 == U2:
        if S1 != S2:
            return (0, 0, 1)
        return jacobianDouble((Xp, Yp, Zp), A, P)
    H = U2 - U1
    R = S2 - S1
    H2 = (H * H) % P
    H3 = (H * H2) % P
    U1H2 = (U1 * H2) % P
    nx = (R ** 2 - H3 - 2 * U1H2) % P
    ny = (R * (U1H2 - nx) - S1 * H3) % P
    nz = (H * Zp * Zq) % P
    return (nx, ny, nz)


def jacobianMultiply((Xp, Yp, Zp), n, N, A, P):
    """
    Multily point and scalar in elliptic curves

    :param (Xp,Yp,Zp): First Point to mutiply
    :param n: Scalar to mutiply
    :param N: Order of the elliptic curve
    :param P: Prime number in the module of the equation Y^2 = X^3 + A*X + B (mod p)
    :param A: Coefficient of the first-order term of the equation Y^2 = X^3 + A*X + B (mod p)
    :return: Point that represents the sum of First and Second Point
    """
    if Yp == 0 or n == 0:
        return (0, 0, 1)
    if n == 1:
        return (Xp, Yp, Zp)
    if n < 0 or n >= N:
        return jacobianMultiply((Xp, Yp, Zp), n % N, N, A, P)
    if (n % 2) == 0:
        return jacobianDouble(jacobianMultiply((Xp, Yp, Zp), n // 2, N, A, P), A, P)
    if (n % 2) == 1:
        return jacobianAdd(jacobianDouble(jacobianMultiply((Xp, Yp, Zp), n // 2, N, A, P), A, P), (Xp, Yp, Zp), A, P)


def numberFrom(string):
    """
    Get a number representation of a string

    :param String to be converted in a number
    :return: Number in hex from string
    """
    return int(hexlify(string), 16)