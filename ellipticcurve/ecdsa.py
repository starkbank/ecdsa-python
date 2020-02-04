from hashlib import sha256
from .utils.compatibility import toBytes
from .signature import Signature
from .math import Math
from .utils.binary import BinaryAscii
from .utils.integer import RandomInteger
from .utils.compatibility import toBytes


class Ecdsa:

    @classmethod
    def sign(cls, message, privateKey, hashfunc=sha256):
        hashMessage = hashfunc(toBytes(message)).digest()
        numberMessage = BinaryAscii.numberFromString(hashMessage)
        curve = privateKey.curve
        randNum = RandomInteger.between(1, curve.N - 1)
        randSignPoint = Math.multiply(curve.G, n=randNum, A=curve.A, P=curve.P, N=curve.N)
        r = randSignPoint.x % curve.N
        s = ((numberMessage + r * privateKey.secret) * (Math.inv(randNum, curve.N))) % curve.N
        return Signature(r, s)

    @classmethod
    def verify(cls, message, signature, publicKey, hashfunc=sha256):
        hashMessage = hashfunc(toBytes(message)).digest()
        numberMessage = BinaryAscii.numberFromString(hashMessage)
        curve = publicKey.curve
        sigR = signature.r
        sigS = signature.s
        inv = Math.inv(sigS, curve.N)
        u1 = Math.multiply(curve.G, n=(numberMessage * inv) % curve.N, A=curve.A, P=curve.P, N=curve.N)
        u2 = Math.multiply(publicKey.point, n=(sigR * inv) % curve.N, A=curve.A, P=curve.P, N=curve.N)
        add = Math.add(u1, u2, P=curve.P, A=curve.A)
        return sigR == add.x
