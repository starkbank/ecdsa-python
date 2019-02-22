from hashlib import sha256
from random import SystemRandom
from .signature import Signature
from .math import multiply, inv, add
from .utils.binary import BinaryAscii


class Ecdsa:

    @classmethod
    def sign(cls, message, privateKey, hashfunc=sha256):
        hashMessage = hashfunc(message.encode()).digest()
        numberMessage = BinaryAscii.numberFromString(hashMessage)
        curve = privateKey.curve
        randNum = SystemRandom().randrange(1, curve.N)
        randSignPoint = multiply(curve.G, n=randNum, A=curve.A, P=curve.P, N=curve.N)
        r = randSignPoint.x % curve.N
        s = ((numberMessage + r * privateKey.secret) * (inv(randNum, curve.N))) % curve.N
        return Signature(r, s)

    @classmethod
    def verify(cls, message, signature, publicKey, hashfunc=sha256):
        hashMessage = hashfunc(message.encode()).digest()
        numberMessage = BinaryAscii.numberFromString(hashMessage)
        curve = publicKey.curve
        r = signature.r
        s = signature.s
        w = inv(s, curve.N)
        u1 = multiply(curve.G, n=(numberMessage * w) % curve.N, A=curve.A, P=curve.P, N=curve.N)
        u2 = multiply(publicKey.point, n=(r * w) % curve.N, A=curve.A, P=curve.P, N=curve.N)
        p = add(u1, u2, P=curve.P, A=curve.A)
        return r == p.x
