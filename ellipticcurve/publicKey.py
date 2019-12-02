from .utils.compatibility import *
from .utils.der import fromPem, removeSequence, removeObject, removeBitString, toPem, encodeSequence, encodeOid, encodeBitString
from .utils.binary import BinaryAscii
from .point import Point
from .curve import curvesByOid, supportedCurves, secp256k1


class PublicKey:

    def __init__(self, point, curve):
        self.point = point
        self.curve = curve

    def toString(self, encoded=False):
        xString = BinaryAscii.stringFromNumber(
            number=self.point.x,
            length=self.curve.length(),
        )
        yString = BinaryAscii.stringFromNumber(
            number=self.point.y,
            length=self.curve.length(),
        )
        return "\x00\x04" + xString + yString if encoded else xString + yString

    def toDer(self):
        oidEcPublicKey = (1, 2, 840, 10045, 2, 1)
        encodeEcAndOid = encodeSequence(
            encodeOid(*oidEcPublicKey),
            encodeOid(*self.curve.oid),
        )

        return encodeSequence(encodeEcAndOid, encodeBitString(self.toString(encoded=True)))

    def toPem(self):
        return toPem(der=toBytes(self.toDer()), name="PUBLIC KEY")

    @classmethod
    def fromPem(cls, string):
        return cls.fromDer(fromPem(string))

    @classmethod
    def fromDer(cls, string):
        s1, empty = removeSequence(string)
        if len(empty) != 0:
            raise Exception("trailing junk after DER public key: {}".format(
                BinaryAscii.hexFromBinary(empty)
            ))

        s2, pointBitString = removeSequence(s1)

        oidPk, rest = removeObject(s2)

        oidCurve, empty = removeObject(rest)
        if len(empty) != 0:
            raise Exception("trailing junk after DER public key objects: {}".format(
                BinaryAscii.hexFromBinary(empty)
            ))

        if oidCurve not in curvesByOid:
            raise Exception(
                "Unknown curve with oid %s. Only the following are available: %s" % (
                    oidCurve,
                    ", ".join([curve.name for curve in supportedCurves])
                )
            )

        curve = curvesByOid[oidCurve]

        pointStr, empty = removeBitString(pointBitString)
        if len(empty) != 0:
            raise Exception(
                "trailing junk after public key point-string: " +
                BinaryAscii.hexFromBinary(empty)
            )

        return cls.fromString(pointStr[2:], curve)

    @classmethod
    def fromString(cls, string, curve=secp256k1, validatePoint=True):
        baseLen = curve.length()

        xs = string[:baseLen]
        ys = string[baseLen:]

        p = Point(
            x=BinaryAscii.numberFromString(xs),
            y=BinaryAscii.numberFromString(ys),
        )

        if validatePoint and not curve.contains(p):
            raise Exception(
                "point ({x},{y}) is not valid for curve {name}".format(
                    x=p.x, y=p.y, name=curve.name
                )
            )

        return PublicKey(point=p, curve=curve)
