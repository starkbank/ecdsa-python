from binascii import hexlify
from .curve import curvesByOid, supportedCurves, secp256k1
from .der import fromPem, removeSequence, removeObject, removeBitString, toPem, encodeSequence, encodeOid, encodeBitstring
from .math import numberFrom, stringFrom


class PublicKey:

    def __init__(self, x, y, curve):
        self.x = x
        self.y = y
        self.curve = curve

    def toString(self, encoded=False):
        Xstr = stringFrom(number=self.x, length=self.curve.length())
        Ystr = stringFrom(number=self.y, length=self.curve.length())
        return Xstr + Ystr if not encoded else "\x00\x04" + Xstr + Ystr

    def toDer(self):
        oidEcPublicKey = (1, 2, 840, 10045, 2, 1)
        encodeEcAndOid = encodeSequence(encodeOid(*oidEcPublicKey), encodeOid(*self.curve.oid))
        return encodeSequence(encodeEcAndOid, encodeBitstring(self.toString(encoded=True)))

    def toPem(self):
        return toPem(der=self.toDer(), name="PUBLIC KEY")

    @classmethod
    def fromPem(cls, string):
        return cls.fromDer(fromPem(string))

    @classmethod
    def fromDer(cls, string):
        s1, empty = removeSequence(string)
        if empty != "":
            raise Exception("trailing junk after DER pubkey: {}".format(hexlify(empty)))
        s2, pointStrBitstring = removeSequence(s1)

        oidPk, rest = removeObject(s2)
        oidCurve, empty = removeObject(rest)
        if empty != "":
            raise Exception("trailing junk after DER pubkey objects: {}".format(hexlify(empty)))

        curve = curvesByOid.get(oidCurve)
        if not curve:
            raise Exception("Unknown curve with oid %s. I only know about these: %s" % (
            oidCurve, ", ".join([curve.name for curve in supportedCurves])))
        pointStr, empty = removeBitString(pointStrBitstring)
        if empty != "":
            raise Exception("trailing junk after pubkey pointstring: {}".format(hexlify(empty)))

        return cls.fromString(pointStr[2:], curve)

    @classmethod
    def fromString(cls, string, curve=secp256k1, validatePoint=True):
        baselen = curve.length()

        xs = string[:baselen]
        ys = string[baselen:]

        x = numberFrom(xs)
        y = numberFrom(ys)

        if validatePoint and not curve.contains((x, y)):
            raise Exception("point ({},{}) is not valid".format(x, y))

        return PublicKey(x=x, y=y, curve=curve)