from hashlib import sha256
from random import randint
from .signature import Signature
from .math import multiply, inv, numberFrom, add


class Ecdsa:

    @classmethod
    def sign(cls, message, privateKey, hashfunc=sha256):
        hashMessage = hashfunc(message).digest()
        numberMessage = numberFrom(hashMessage)
        curve = privateKey.curve
        randNum = randint(1, curve.N)
        xRandSignPoint, yRandSignPoint = multiply((curve.Gx, curve.Gy), randNum, A=curve.A, P=curve.P, N=curve.N)
        r = xRandSignPoint % curve.N
        s = ((numberMessage + r * privateKey.secret) * (inv(randNum, curve.N))) % curve.N
        return Signature(r, s)

    @classmethod
    def verify(cls, message, signature, publicKey, hashfunc=sha256):
        hashMessage = hashfunc(message).digest()
        numberMessage = numberFrom(hashMessage)
        curve = publicKey.curve
        Xpk = publicKey.x
        Ypk = publicKey.y
        r = signature.r
        s = signature.s
        w = inv(s, curve.N)
        xu1, yu1 = multiply((curve.Gx, curve.Gy), (numberMessage * w) % curve.N, A=curve.A, P=curve.P, N=curve.N)
        xu2, yu2 = multiply((Xpk, Ypk), (r * w) % curve.N, A=curve.A, P=curve.P, N=curve.N)
        x, y = add((xu1, yu1), (xu2, yu2), P=curve.P, A=curve.A)
        return r == x