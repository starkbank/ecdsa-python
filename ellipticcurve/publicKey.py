from binascii import hexlify
from .curve import curvesByOid, supportedCurves, secp256k1
from .der import fromPem, removeSequence, removeObject, removeBitString
from .math import numberFrom


class PublicKey:

    def __init__(self, x, y, curve):
        self.x = x
        self.y = y
        self.curve = curve

    def toString(self, compressed=True):
        return {
            True:  "020{}".format(str(hex(self.x))[2:-1]),
            False: "040{}{}".format(str(hex(self.x))[2:-1], str(hex(self.y))[2:-1])
        }.get(compressed)

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