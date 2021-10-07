from ellipticcurve.utils.binary import intFromHex, hexFromInt


def oidFromHex(hexadecimal):
    firstByte, remainingBytes = hexadecimal[:2], hexadecimal[2:]
    firstByteInt = intFromHex(firstByte)
    oid = [firstByteInt // 40, firstByteInt % 40]
    oidInt = 0
    while len(remainingBytes) > 0:
        byte, remainingBytes = remainingBytes[0:2], remainingBytes[2:]
        byteInt = intFromHex(byte)
        if byteInt >= 128:
            oidInt = byteInt - 128
            continue
        oidInt = oidInt * 128 + byteInt
        oid.append(oidInt)
        oidInt = 0
    return oid


def oidToHex(oid):
    hexadecimal = hexFromInt(40 * oid[0] + oid[1])
    byteArray = []
    for oidInt in oid[2:]:
        endDelta = 0
        while True:
            byteInt = oidInt % 128 + endDelta
            oidInt = oidInt // 128
            endDelta = 128
            byteArray.append(byteInt)
            if oidInt == 0:
                break
        hexadecimal += "".join(hexFromInt(byteInt).zfill(2) for byteInt in reversed(byteArray))
        byteArray = []
    return hexadecimal
