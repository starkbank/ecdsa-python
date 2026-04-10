from hmac import new as hmacNew
from .binary import numberFromByteString, hexFromInt, byteStringFromHex

try:
    from secrets import randbelow as _randbelow
except ImportError:
    from random import SystemRandom
    _systemRandom = SystemRandom()
    _randbelow = lambda n: _systemRandom.randrange(n)


class RandomInteger:

    @classmethod
    def between(cls, min, max):
        """
        Return integer x in the range: min <= x <= max

        :param min: minimum value of the integer
        :param max: maximum value of the integer
        :return:
        """

        return min + _randbelow(max - min + 1)

    @classmethod
    def rfc6979(cls, hashBytes, secret, curve, hashfunc):
        """Generate deterministic nonce values per RFC 6979"""
        orderBitLen = curve.N.bit_length()
        orderByteLen = (orderBitLen + 7) // 8

        secretHex = hexFromInt(secret).zfill(orderByteLen * 2)
        secretBytes = byteStringFromHex(secretHex)

        hashReduced = numberFromByteString(hashBytes, orderBitLen) % curve.N
        hashHex = hexFromInt(hashReduced).zfill(orderByteLen * 2)
        hashOctets = byteStringFromHex(hashHex)

        hLen = hashfunc().digest_size
        V = b'\x01' * hLen
        K = b'\x00' * hLen

        K = hmacNew(K, V + b'\x00' + secretBytes + hashOctets, hashfunc).digest()
        V = hmacNew(K, V, hashfunc).digest()
        K = hmacNew(K, V + b'\x01' + secretBytes + hashOctets, hashfunc).digest()
        V = hmacNew(K, V, hashfunc).digest()

        while True:
            T = b''
            while len(T) * 8 < orderBitLen:
                V = hmacNew(K, V, hashfunc).digest()
                T += V

            k = numberFromByteString(T, orderBitLen)

            if 1 <= k <= curve.N - 1:
                yield k

            K = hmacNew(K, V + b'\x00', hashfunc).digest()
            V = hmacNew(K, V, hashfunc).digest()
