from random import randint
from .publicKey import PublicKey
from .math import multiply
from .curve import secp256k1


class PrivateKey:

    def __init__(self, curve=secp256k1):
        self.curve = curve
        self.secret = randint(1, curve.N)

    def publicKey(self):
        curve = self.curve
        xPublicKey, yPublicKey = multiply((curve.Gx, curve.Gy), self.secret, A=curve.A, P=curve.P, N=curve.N)
        return PublicKey(xPublicKey, yPublicKey, curve)

    def toString(self):
        return "020{}".format(str(hex(self.secret))[2:-1])