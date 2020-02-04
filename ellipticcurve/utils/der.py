from .base import Base64
from .binary import BinaryAscii
from .compatibility import *


hexAt = "\x00"
hexB = "\x02"
hexC = "\x03"
hexD = "\x04"
hexF = "\x06"
hex0 = "\x30"

hex31 = 0x1f
hex127 = 0x7f
hex129 = 0xa0
hex160 = 0x80
hex224 = 0xe0

bytesHex0 = toBytes(hex0)
bytesHexB = toBytes(hexB)
bytesHexC = toBytes(hexC)
bytesHexD = toBytes(hexD)
bytesHexF = toBytes(hexF)


def encodeSequence(*encodedPieces):
    totalLengthLen = sum([len(p) for p in encodedPieces])
    return hex0 + _encodeLength(totalLengthLen) + "".join(encodedPieces)


def encodeInteger(x):
    assert x >= 0
    t = ("%x" % x).encode()

    if len(t) % 2:
        t = toBytes("0") + t

    x = BinaryAscii.binaryFromHex(t)
    num = x[0] if isinstance(x[0], intTypes) else ord(x[0])

    if num <= hex127:
        return hexB + chr(len(x)) + toString(x)
    return hexB + chr(len(x) + 1) + hexAt + toString(x)


def encodeOid(first, second, *pieces):
    assert first <= 2
    assert second <= 39

    encodedPieces = [chr(40 * first + second)] + [_encodeNumber(p) for p in pieces]
    body = "".join(encodedPieces)

    return hexF + _encodeLength(len(body)) + body


def encodeBitString(t):
    return hexC + _encodeLength(len(t)) + t


def encodeOctetString(t):
    return hexD + _encodeLength(len(t)) + t


def encodeConstructed(tag, value):
    return chr(hex129 + tag) + _encodeLength(len(value)) + value


def removeSequence(string):
    _checkSequenceError(string=string, start=bytesHex0, expected="30")

    length, lengthLen = _readLength(string[1:])
    endSeq = 1 + lengthLen + length

    return string[1 + lengthLen: endSeq], string[endSeq:]


def removeInteger(string):
    _checkSequenceError(string=string, start=bytesHexB, expected="02")

    length, lengthLen = _readLength(string[1:])
    numberBytes = string[1 + lengthLen:1 + lengthLen + length]
    rest = string[1 + lengthLen + length:]
    nBytes = numberBytes[0] if isinstance(
        numberBytes[0], intTypes
    ) else ord(numberBytes[0])

    assert nBytes < hex160

    return int(BinaryAscii.hexFromBinary(numberBytes), 16), rest


def removeObject(string):
    _checkSequenceError(string=string, start=bytesHexF, expected="06")

    length, lengthLen = _readLength(string[1:])
    body = string[1 + lengthLen:1 + lengthLen + length]
    rest = string[1 + lengthLen + length:]
    numbers = []

    while body:
        n, lengthLength = _readNumber(body)
        numbers.append(n)
        body = body[lengthLength:]

    n0 = numbers.pop(0)
    first = n0 // 40
    second = n0 - (40 * first)
    numbers.insert(0, first)
    numbers.insert(1, second)

    return tuple(numbers), rest


def removeBitString(string):
    _checkSequenceError(string=string, start=bytesHexC, expected="03")

    length, lengthLen = _readLength(string[1:])
    body = string[1 + lengthLen:1 + lengthLen + length]
    rest = string[1 + lengthLen + length:]

    return body, rest


def removeOctetString(string):
    _checkSequenceError(string=string, start=bytesHexD, expected="04")

    length, lengthLen = _readLength(string[1:])
    body = string[1 + lengthLen:1 + lengthLen + length]
    rest = string[1 + lengthLen + length:]

    return body, rest


def removeConstructed(string):
    s0 = _extractFirstInt(string)
    if (s0 & hex224) != hex129:
        raise Exception("wanted constructed tag (0xa0-0xbf), got 0x%02x" % s0)

    tag = s0 & hex31
    length, lengthLen = _readLength(string[1:])
    body = string[1 + lengthLen:1 + lengthLen + length]
    rest = string[1 + lengthLen + length:]

    return tag, body, rest


def fromPem(pem):
    t = "".join([
        l.strip() for l in pem.splitlines()
        if l and not l.startswith("-----")
    ])
    return Base64.decode(t)


def toPem(der, name):
    b64 = toString(Base64.encode(der))
    lines = ["-----BEGIN " + name + "-----\n"]
    lines.extend([
        b64[start:start + 64] + '\n'
        for start in xrange(0, len(b64), 64)
    ])
    lines.append("-----END " + name + "-----\n")

    return "".join(lines)


def _encodeLength(length):
    assert length >= 0

    if length < hex160:
        return chr(length)

    s = ("%x" % length).encode()
    if len(s) % 2:
        s = "0" + s

    s = BinaryAscii.binaryFromHex(s)
    lengthLen = len(s)

    return chr(hex160 | lengthLen) + str(s)


def _encodeNumber(n):
    b128Digits = []
    while n:
        b128Digits.insert(0, (n & hex127) | hex160)
        n >>= 7

    if not b128Digits:
        b128Digits.append(0)

    b128Digits[-1] &= hex127

    return "".join([chr(d) for d in b128Digits])


def _readLength(string):
    num = _extractFirstInt(string)
    if not (num & hex160):
        return (num & hex127), 1

    lengthLen = num & hex127

    if lengthLen > len(string) - 1:
        raise Exception("ran out of length bytes")

    return int(BinaryAscii.hexFromBinary(string[1:1 + lengthLen]), 16), 1 + lengthLen


def _readNumber(string):
    number = 0
    lengthLen = 0
    while True:
        if lengthLen > len(string):
            raise Exception("ran out of length bytes")

        number <<= 7
        d = string[lengthLen]
        if not isinstance(d, intTypes):
            d = ord(d)

        number += (d & hex127)
        lengthLen += 1
        if not d & hex160:
            break

    return number, lengthLen


def _checkSequenceError(string, start, expected):
    if not string.startswith(start):
        raise Exception(
            "wanted sequence (0x%s), got 0x%02x" %
            (expected, _extractFirstInt(string))
        )


def _extractFirstInt(string):
    return string[0] if isinstance(string[0], intTypes) else ord(string[0])
