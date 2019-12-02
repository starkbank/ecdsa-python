from .utils.integer import RandomInteger
from .utils.compatibility import *
from .utils.binary import BinaryAscii
from .utils.der import fromPem, removeSequence, removeInteger, removeObject, removeOctetString, removeConstructed, toPem, encodeSequence, encodeInteger, encodeBitString, encodeOid, encodeOctetString, encodeConstructed
from .publicKey import PublicKey
from .curve import secp256k1, curvesByOid, supportedCurves
from .math import Math

hexAt = "\x00"


class PrivateKey:

    def __init__(self, curve=secp256k1, secret=None):
        self.curve = curve
        self.secret = secret or RandomInteger.between(1, curve.N - 1)

    def publicKey(self):
        curve = self.curve
        publicPoint = Math.multiply(
            p=curve.G,
            n=self.secret,
            N=curve.N,
            A=curve.A,
            P=curve.P,
        )
        return PublicKey(point=publicPoint, curve=curve)

    def toString(self):
        return BinaryAscii.stringFromNumber(number=self.secret, length=self.curve.length())

    def toDer(self):
        encodedPublicKey = self.publicKey().toString(encoded=True)

        return encodeSequence(
            encodeInteger(1),
            encodeOctetString(self.toString()),
            encodeConstructed(0, encodeOid(*self.curve.oid)),
            encodeConstructed(1, encodeBitString(encodedPublicKey)),
        )

    def toPem(self):
        return toPem(der=toBytes(self.toDer()), name="EC PRIVATE KEY")

    @classmethod
    def fromPem(cls, string):
        privateKeyPem = string[string.index("-----BEGIN EC PRIVATE KEY-----"):]
        return cls.fromDer(fromPem(privateKeyPem))

    @classmethod
    def fromDer(cls, string):
        t, empty = removeSequence(string)
        if len(empty) != 0:
            raise Exception(
                "trailing junk after DER private key: " +
                BinaryAscii.hexFromBinary(empty)
            )

        one, t = removeInteger(t)
        if one != 1:
            raise Exception(
                "expected '1' at start of DER private key, got %d" % one
            )

        privateKeyStr, t = removeOctetString(t)
        tag, curveOidStr, t = removeConstructed(t)
        if tag != 0:
            raise Exception("expected tag 0 in DER private key, got %d" % tag)

        oidCurve, empty = removeObject(curveOidStr)

        if len(empty) != 0:
            raise Exception(
                "trailing junk after DER private key curve_oid: %s" %
                BinaryAscii.hexFromBinary(empty)
            )

        if oidCurve not in curvesByOid:
            raise Exception(
                "unknown curve with oid %s; The following are registered: %s" % (
                    oidCurve,
                    ", ".join([curve.name for curve in supportedCurves])
                )
            )

        curve = curvesByOid[oidCurve]

        if len(privateKeyStr) < curve.length():
            privateKeyStr = hexAt * (curve.lenght() - len(privateKeyStr)) + privateKeyStr

        return cls.fromString(privateKeyStr, curve)

    @classmethod
    def fromString(cls, string, curve=secp256k1):
        return PrivateKey(secret=BinaryAscii.numberFromString(string), curve=curve)
