from hashlib import sha256
from .signature import Signature
from .math import Math
from .utils.integer import RandomInteger
from .utils.binary import numberFromByteString
from .utils.compatibility import *


class Ecdsa:

    @classmethod
    def sign(cls, message, privateKey, hashfunc=sha256):
        curve = privateKey.curve
        byteMessage = hashfunc(toBytes(message)).digest()
        numberMessage = numberFromByteString(byteMessage, curve.nBitLength)

        r, s, randSignPoint = 0, 0, None
        kIterator = RandomInteger.rfc6979(byteMessage, privateKey.secret, curve, hashfunc)
        while r == 0 or s == 0:
            randNum = next(kIterator)
            randSignPoint = Math.multiplyGenerator(curve, randNum)
            r = randSignPoint.x % curve.N
            s = ((numberMessage + r * privateKey.secret) * (Math.inv(randNum, curve.N))) % curve.N
        recoveryId = randSignPoint.y & 1
        if randSignPoint.x >= curve.N:
            recoveryId += 2
        if s > curve.N // 2:
            s = curve.N - s
            recoveryId ^= 1

        return Signature(r=r, s=s, recoveryId=recoveryId)

    @classmethod
    def verify(cls, message, signature, publicKey, hashfunc=sha256):
        curve = publicKey.curve
        byteMessage = hashfunc(toBytes(message)).digest()
        numberMessage = numberFromByteString(byteMessage, curve.nBitLength)
        r = signature.r
        s = signature.s

        if not 1 <= r <= curve.N - 1:
            return False
        if not 1 <= s <= curve.N - 1:
            return False
        if not curve.contains(publicKey.point):
            return False
        inv = Math.inv(s, curve.N)
        v = Math.multiplyAndAdd(
            curve.G, (numberMessage * inv) % curve.N,
            publicKey.point, (r * inv) % curve.N,
            curve=curve,
        )
        if v.isAtInfinity():
            return False
        return v.x % curve.N == r
