from binascii import hexlify
from .der import encodeSequence, encodeInteger, removeSequence, removeInteger


class Signature:

    def __init__(self, r, s):
        self.r = r
        self.s = s

    def toDer(self):
        return encodeSequence(encodeInteger(self.r), encodeInteger(self.s))

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