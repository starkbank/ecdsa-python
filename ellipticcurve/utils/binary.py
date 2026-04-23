from base64 import b64encode, b64decode
from .compatibility import safeHexFromBinary, safeBinaryFromHex, toString


def hexFromInt(number):
    hexadecimal = "{0:x}".format(number)
    if len(hexadecimal) % 2 == 1:
        hexadecimal = "0" + hexadecimal
    return hexadecimal


def intFromHex(hexadecimal):
    return int(hexadecimal, 16)


def hexFromByteString(byteString):
    return safeHexFromBinary(byteString)


def byteStringFromHex(hexadecimal):
    return safeBinaryFromHex(hexadecimal)


def numberFromByteString(byteString, bitLength=None):
    number = intFromHex(hexFromByteString(byteString))
    if bitLength is not None:
        hashBitLen = len(byteString) * 8
        if hashBitLen > bitLength:
            number >>= (hashBitLen - bitLength)
    return number


def base64FromByteString(byteString):
    return toString(b64encode(byteString))


def byteStringFromBase64(base64String):
    return b64decode(base64String)


def bitsFromHex(hexadecimal):
    return format(intFromHex(hexadecimal), 'b').zfill(4 * len(hexadecimal))
