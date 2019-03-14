from sys import version_info as pyVersion
from binascii import hexlify, unhexlify


if pyVersion.major == 3:
    # py3 constants and conversion functions

    xrange = range
    stringTypes = (str)
    intTypes = (int, float)

    def toString(string):
        return string.decode("latin-1")

    def toBytes(string):
        return string.encode("latin-1")

    def safeBinaryFromHex(hexString):
        return unhexlify(hexString)

    def safeHexFromBinary(byteString):
        return hexlify(byteString)
else:
    # py2 constants and conversion functions
    stringTypes = (str, unicode)
    intTypes = (int, float, long)

    def toString(string):
        return string

    def toBytes(string):
        return string

    def safeBinaryFromHex(hexString):
        return unhexlify(hexString)

    def safeHexFromBinary(byteString):
        return hexlify(byteString)
