from .utils.compatibility import *
from .utils.base import Base64
from .utils.binary import BinaryAscii
from .utils.der import encodeSequence, encodeInteger, removeSequence, removeInteger


class Signature:

    def __init__(self, r, s, recoveryId=None):
        self.r = r
        self.s = s
        self.recoveryId = recoveryId

    def toDer(self, withRecoveryId=False):
        encodedSequence = encodeSequence(encodeInteger(self.r), encodeInteger(self.s))
        if not withRecoveryId:
            return encodedSequence
        return chr(27 + self.recoveryId) + encodedSequence

    def toBase64(self, withRecoveryId=False):
        return toString(Base64.encode(toBytes(self.toDer(withRecoveryId=withRecoveryId))))

    @classmethod
    def fromDer(cls, string, recoveryByte=False):
        recoveryId = None
        if recoveryByte:
            recoveryId = string[0] if isinstance(string[0], intTypes) else ord(string[0])
            recoveryId -= 27
            string = string[1:]

        rs, empty = removeSequence(string)
        if len(empty) != 0:
            raise Exception("trailing junk after DER signature: %s" % BinaryAscii.hexFromBinary(empty))

        r, rest = removeInteger(rs)
        s, empty = removeInteger(rest)
        if len(empty) != 0:
            raise Exception("trailing junk after DER numbers: %s" % BinaryAscii.hexFromBinary(empty))

        return Signature(r=r, s=s, recoveryId=recoveryId)

    @classmethod
    def fromBase64(cls, string, recoveryByte=False):
        der = Base64.decode(string)
        return cls.fromDer(der, recoveryByte)
