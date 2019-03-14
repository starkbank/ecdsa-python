from .base import Base64
from .binary import BinaryAscii
from .compatibility import *


def encodeSequence(*encodedPieces):
    totalLen = sum([len(p) for p in encodedPieces])
    return "\x30" + encodeLength(totalLen) + "".join(encodedPieces)


def encodeLength(length):
    assert length >= 0
    if length < 0x80:
        return chr(length)
    s = ("%x" % length).encode()
    if len(s) % 2:
        s = "0" + s

    s = BinaryAscii.binaryFromHex(s)
    llen = len(s)
    return chr(0x80 | llen) + str(s)


def encodeInteger(x):
    assert x >= 0
    t = ("%x" % x).encode()

    if len(t) % 2:
        t = toBytes("0") + t

    x = BinaryAscii.binaryFromHex(t)
    num = x[0] if isinstance(x[0], intTypes) else ord(x[0])
    if num <= 0x7f:
        return "\x02" + chr(len(x)) + toString(x)
    return "\x02" + chr(len(x)+1) + "\x00" + toString(x)


def encodeNumber(n):
    b128Digits = []
    while n:
        b128Digits.insert(0, (n & 0x7f) | 0x80)
        n = n >> 7
    if not b128Digits:
        b128Digits.append(0)
    b128Digits[-1] &= 0x7f
    return "".join([chr(d) for d in b128Digits])


def encodeOid(first, second, *pieces):
    assert first <= 2
    assert second <= 39
    encodedPieces = [chr(40*first+second)] + [encodeNumber(p) for p in pieces]
    body = "".join(encodedPieces)
    return "\x06" + encodeLength(len(body)) + body


def encodeBitstring(t):
    return "\x03" + encodeLength(len(t)) + t


def encodeOctetString(t):
    return "\x04" + encodeLength(len(t)) + t


def encodeConstructed(tag, value):
    return chr(0xa0+tag) + encodeLength(len(value)) + value


def readLength(string):
    num = string[0] if isinstance(string[0], intTypes) else ord(string[0])
    if not (num & 0x80):
        return (num & 0x7f), 1

    llen = num & 0x7f
    if llen > len(string)-1:
        raise Exception("ran out of length bytes")
    return int(BinaryAscii.hexFromBinary(string[1:1 + llen]), 16), 1 + llen


def readNumber(string):
    number = 0
    llen = 0
    while True:
        if llen > len(string):
            raise Exception("ran out of length bytes")
        number = number << 7
        d = string[llen] if isinstance(string[llen], intTypes) else ord(string[llen])
        number += (d & 0x7f)
        llen += 1
        if not d & 0x80:
            break
    return number, llen


def removeSequence(string):
    if not string.startswith(toBytes("\x30")):
        x = string[0] if isinstance(string[0], intTypes) else ord(string[0])
        raise Exception("wanted sequence (0x30), got 0x%02x" % x)
    length, lengthlength = readLength(string[1:])
    endseq = 1+lengthlength+length
    return string[1+lengthlength:endseq], string[endseq:]


def removeInteger(string):  
    if not string.startswith(toBytes("\x02")):
        n = string[0] if isinstance(string[0], intTypes) else ord(string[0])
        raise Exception("wanted integer (0x02), got 0x%02x" % n)
    length, llen = readLength(string[1:])
    numberbytes = string[1+llen:1+llen+length]
    rest = string[1+llen+length:]
    nbytes = numberbytes[0] if isinstance(numberbytes[0], intTypes) else ord(numberbytes[0])
    assert nbytes < 0x80

    return int(BinaryAscii.hexFromBinary(numberbytes), 16), rest


def removeObject(string):
    if not string.startswith(toBytes("\x06")):
        n = string[0] if isinstance(string[0], intTypes) else ord(string[0])
        raise Exception("wanted object (0x06), got 0x%02x" % n)
    length, lengthlength = readLength(string[1:])
    body = string[1 + lengthlength:1 + lengthlength + length]
    rest = string[1 + lengthlength + length:]
    numbers = []
    while body:
        n, ll = readNumber(body)
        numbers.append(n)
        body = body[ll:]
    n0 = numbers.pop(0)
    first = n0 // 40
    second = n0 - (40 * first)
    numbers.insert(0, first)
    numbers.insert(1, second)

    return tuple(numbers), rest


def removeBitString(string):
    num = string[0] if isinstance(string[0], intTypes) else ord(string[0])
    if not string.startswith(toBytes("\x03")):
        raise Exception("wanted bitstring (0x03), got 0x%02x" % num)
    length, llen = readLength(string[1:])
    body = string[1 + llen:1 + llen + length]
    rest = string[1 + llen + length:]
    return body, rest


def removeOctetString(string):
    if not string.startswith(toBytes("\x04")):
        n = string[0] if isinstance(string[0], intTypes) else ord(string[0])
        raise Exception("wanted octetstring (0x04), got 0x%02x" % n)
    length, llen = readLength(string[1:])
    body = string[1+llen:1+llen+length]
    rest = string[1+llen+length:]
    return body, rest


def removeConstructed(string):
    s0 = string[0] if isinstance(string[0], intTypes) else ord(string[0])
    if (s0 & 0xe0) != 0xa0:
        raise Exception("wanted constructed tag (0xa0-0xbf), got 0x%02x" % s0)
    tag = s0 & 0x1f
    length, llen = readLength(string[1:])
    body = string[1+llen:1+llen+length]
    rest = string[1+llen+length:]
    return tag, body, rest


def fromPem(pem):
    t = "".join([l.strip() for l in pem.split("\n") if l and not l.startswith("-----")])
    return Base64.decode(t)


def toPem(der, name):
    b64 = toString(Base64.encode(der))
    lines = [("-----BEGIN " + name + "-----\n")]
    lines.extend([b64[start:start+64] + '\n' for start in xrange(0, len(b64), 64)])
    lines.append("-----END " + name + "-----\n")
    return "".join(lines)
