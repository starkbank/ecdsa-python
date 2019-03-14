from .utils.compatibility import *
from .utils.der import fromPem, removeSequence, removeObject, removeBitString, toPem, encodeSequence, encodeOid, encodeBitstring
from .utils.binary import BinaryAscii
from .point import Point
from .curve import curvesByOid, supportedCurves, secp256k1


class PublicKey:

    def __init__(self, point, curve):
        self.point = point
        self.curve = curve

    def toString(self, encoded=False):
        Xstr = BinaryAscii.stringFromNumber(number=self.point.x, length=self.curve.length())
        Ystr = BinaryAscii.stringFromNumber(number=self.point.y, length=self.curve.length())
        return Xstr + Ystr if not encoded else "\x00\x04" + Xstr + Ystr

    def toDer(self):
        oidEcPublicKey = (1, 2, 840, 10045, 2, 1)
        encodeEcAndOid = encodeSequence(encodeOid(*oidEcPublicKey), encodeOid(*self.curve.oid))
        return encodeSequence(encodeEcAndOid, encodeBitstring(self.toString(encoded=True)))

    def toPem(self):
        return toPem(der=toBytes(self.toDer()), name="PUBLIC KEY")

    @classmethod
    def fromPem(cls, string):
        return cls.fromDer(fromPem(string))

    @classmethod
    def fromDer(cls, string):
        s1, empty = removeSequence(string)
        if len(empty) != 0:
            raise Exception("trailing junk after DER pubkey: {}".format(BinaryAscii.hexFromBinary(empty)))
        s2, pointStrBitstring = removeSequence(s1)


        oidPk, rest = removeObject(s2)
        
        oidCurve, empty = removeObject(rest)
        if len(empty) != 0:
            raise Exception("trailing junk after DER pubkey objects: {}".format(BinaryAscii.hexFromBinary(empty)))

        curve = curvesByOid.get(oidCurve)
        if not curve:
            raise Exception("Unknown curve with oid %s. I only know about these: %s" % (
            oidCurve, ", ".join([curve.name for curve in supportedCurves])))
        pointStr, empty = removeBitString(pointStrBitstring)
        if len(empty) != 0:
            raise Exception("trailing junk after pubkey pointstring: {}".format(BinaryAscii.hexFromBinary(empty)))

        return cls.fromString(pointStr[2:], curve)

    @classmethod
    def fromString(cls, string, curve=secp256k1, validatePoint=True):
        baselen = curve.length()

        xs = string[:baselen]
        ys = string[baselen:]

        p = Point(x=BinaryAscii.numberFromString(xs), y=BinaryAscii.numberFromString(ys))

        if validatePoint and not curve.contains(p):
            raise Exception("point ({x},{y}) is not valid".format(x=p.x, y=p.y))

        return PublicKey(point=p, curve=curve)
