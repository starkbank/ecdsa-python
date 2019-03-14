from .utils.integer import RandomInteger
from .utils.compatibility import *
from .utils.binary import BinaryAscii
from .utils.der import fromPem, removeSequence, removeInteger, removeObject, removeOctetString, removeConstructed, toPem, encodeSequence, encodeInteger, encodeBitstring, encodeOid, encodeOctetString, encodeConstructed
from .publicKey import PublicKey
from .curve import secp256k1, curvesByOid, supportedCurves
from .math import Math


class PrivateKey:

    def __init__(self, curve=secp256k1, secret=None):
        self.curve = curve
        self.secret = secret or RandomInteger.between(1, curve.N - 1)

    def publicKey(self):
        curve = self.curve
        publicPoint = Math.multiply(curve.G, n=self.secret, A=curve.A, P=curve.P, N=curve.N)
        return PublicKey(point=publicPoint, curve=curve)

    def toString(self):
        return BinaryAscii.stringFromNumber(number=self.secret, length=self.curve.length())

    def toDer(self):
        encodedPublicKey = self.publicKey().toString(encoded=True)
        return encodeSequence(
            encodeInteger(1),
            encodeOctetString(self.toString()),
            encodeConstructed(0, encodeOid(*self.curve.oid)),
            encodeConstructed(1, encodeBitstring(encodedPublicKey)),
        )

    def toPem(self):
        return toPem(der=toBytes(self.toDer()), name="EC PRIVATE KEY")

    @classmethod
    def fromPem(cls, string):
        privkeyPem = string[string.index("-----BEGIN EC PRIVATE KEY-----"):]
        return cls.fromDer(fromPem(privkeyPem))

    @classmethod
    def fromDer(cls, string):
        t, empty = removeSequence(string)
        if len(empty) != 0:
            raise Exception("trailing junk after DER privkey: %s" % BinaryAscii.hexFromBinary(empty))

        one, t = removeInteger(t)
        if one != 1:
            raise Exception("expected '1' at start of DER privkey, got %d" % one)

        privkeyStr, t = removeOctetString(t)
        tag, curveOidStr, t = removeConstructed(t)
        if tag != 0:
            raise Exception("expected tag 0 in DER privkey, got %d" % tag)

        oidCurve, empty = removeObject(curveOidStr)

        if len(empty) != 0:
            raise Exception("trailing junk after DER privkey curve_oid: %s" % BinaryAscii.hexFromBinary(empty))

        curve = curvesByOid.get(oidCurve)
        if not curve:
            raise Exception("Unknown curve with oid %s. I only know about these: %s" % (
                oidCurve, ", ".join([curve.name for curve in supportedCurves]))
            )

        if len(privkeyStr) < curve.length():
            privkeyStr = "\x00" * (curve.lenght() - len(privkeyStr)) + privkeyStr

        return cls.fromString(privkeyStr, curve)

    @classmethod
    def fromString(cls, string, curve=secp256k1):
        return PrivateKey(secret=BinaryAscii.numberFromString(string), curve=curve)
