#
# Elliptic Curve Equation
#
# y^2 = x^3 + a*x + b (mod p)
#


class CurveFp:

    def __init__(self, A, B, P, N, Gx, Gy, name):
        self.A = A
        self.B = B
        self.P = P
        self.N = N
        self.Gx = Gx
        self.Gy = Gy
        self.name = name

    def contains(self, (x,y)):
      """Is the point R(x,y) on this curve?"""
      return (y**2 - (x**3 + self.A * x + self.B)) % self.P == 0

    def length(self):
        return (1 + len("%x" % self.N)) // 2


secp256k1 = CurveFp(
    name="secp256k1",
    A=0x0000000000000000000000000000000000000000000000000000000000000000,
    B=0x0000000000000000000000000000000000000000000000000000000000000007,
    P=0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f,
    N=0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141,
    Gx=0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798,
    Gy=0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8
)

supportedCurves = [
    secp256k1
]

curvesByOid = {
    (1, 3, 132, 0, 10): secp256k1
}