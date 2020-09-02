from .utils.compatibility import *
from .utils.base import Base64
from .utils.binary import BinaryAscii
from .utils.der import encodeSequence, encodeInteger, removeSequence, removeInteger


class Signature:

    def __init__(self, r, s, recid=None):
        self.r = r
        self.s = s
        self.recid = recid

    def toDer(self):
        rval = encodeSequence(encodeInteger(self.r), encodeInteger(self.s))
        if self.recid is None:
            return rval
        first = chr(27 + self.recid)
        return first + rval

    def toBase64(self):
        return toString(Base64.encode(toBytes(self.toDer())))

    @classmethod
    def fromDer(cls, string, has_recovery_byte=False):
        recid = None
        if has_recovery_byte:
            recid = ord(string[0]) - 27
            string = string[1:]
        rs, empty = removeSequence(string)
        if len(empty) != 0:
            raise Exception("trailing junk after DER signature: %s" % BinaryAscii.hexFromBinary(empty))

        r, rest = removeInteger(rs)
        s, empty = removeInteger(rest)
        if len(empty) != 0:
            raise Exception("trailing junk after DER numbers: %s" % BinaryAscii.hexFromBinary(empty))
        if recid is None:
            return Signature(r, s)
        return Signature(r, s, recid)

    @classmethod
    def fromBase64(cls, string, has_recovery_byte=False):
        der = Base64.decode(string)
        return cls.fromDer(der, has_recovery_byte)
