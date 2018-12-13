from binascii import hexlify
from base64 import b64encode, b64decode
from .der import encodeSequence, encodeInteger, removeSequence, removeInteger


class Signature:

    def __init__(self, r, s):
        self.r = r
        self.s = s

    def toDer(self):
        return encodeSequence(encodeInteger(self.r), encodeInteger(self.s))

    def toBase64(self):
        return b64encode(self.toDer())

    @classmethod
    def fromDer(cls, string):
        rs, empty = removeSequence(string)
        if empty != "":
            raise Exception("trailing junk after DER sig: %s" % hexlify(empty))
        r, rest = removeInteger(rs)
        s, empty = removeInteger(rest)
        if empty != "":
            raise Exception("trailing junk after DER numbers: %s" % hexlify(empty))
        return Signature(r, s)

    @classmethod
    def fromBase64(cls, string):
        der = b64decode(string)
        return cls.fromDer(der)