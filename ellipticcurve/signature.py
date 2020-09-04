from .utils.compatibility import *
from .utils.base import Base64
from .utils.binary import BinaryAscii
from .utils.der import encodeSequence, encodeInteger, removeSequence, removeInteger


class Signature:

    def __init__(self, r, s, recoveryId=None):
        self.r = r
        self.s = s
        self.recid = recoveryId

    def toDer(self, withRecoveryId=False):
        encodedSequence = encodeSequence(encodeInteger(self.r), encodeInteger(self.s))
        if not withRecoveryId:
            return encodedSequence
        first = chr(27 + self.recid)
        return first + encodedSequence

    def toBase64(self, withRecoveryId=False):
        return toString(Base64.encode(toBytes(self.toDer(withRecoveryId))))

    @classmethod
    def fromDer(cls, string, recoveryByte=False):
        recid = None
        if recoveryByte:
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
    def fromBase64(cls, string, recoveryByte=False):
        der = Base64.decode(string)
        return cls.fromDer(der, recoveryByte)
