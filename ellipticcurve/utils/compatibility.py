import sys, os
import binascii


if sys.version_info.major == 3:
    # py3 constants and conversion functions

    xrange = range
    string_types = (str)
    int_types = (int, float)

    def toLatin(string):
        return str(string, 'latin-1')

    def fromLatin(string):
        return bytes(string, 'latin-1')

    def safeFromHex(s):
        return bytes.fromhex(s.decode())

    def safeHexlify(a):
        return str(binascii.hexlify(a), 'utf-8')

    def toString(string):
        return string.decode('utf-8')

    def toBytes(string):
        return string.encode('latin-1')
else:
    # py2 constants and conversion functions
    string_types = (str, unicode)
    int_types = (int, float, long)

    def toLatin(string):
        return string

    def fromLatin(string):
        return string

    def toString(string):
        return string

    def toBytes(string):
        return string

    def safeFromHex(s):
        return s.decode('hex')

    def safeHexlify(a):
        return binascii.hexlify(a)
