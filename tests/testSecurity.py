from unittest.case import TestCase
from hashlib import sha256, sha512
from ellipticcurve import Ecdsa, PrivateKey, PublicKey, Signature
from ellipticcurve.curve import secp256k1, prime256v1
from ellipticcurve.point import Point
from ellipticcurve.math import Math
from ellipticcurve.utils.binary import hexFromInt


class Rfc6979KnownAnswerTest(TestCase):
    """Test vectors from RFC 6979 Appendix A.2.5 (prime256v1/SHA-256).
    The r values match the RFC exactly; s values are low-S normalized
    (s = N - s when RFC s > N/2)."""

    def setUp(self):
        self.privateKey = PrivateKey(
            curve=prime256v1,
            secret=0xC9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721,
        )
        self.publicKey = self.privateKey.publicKey()

    def testPublicKeyMatchesRfc(self):
        self.assertEqual(
            self.publicKey.point.x,
            0x60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6,
        )
        self.assertEqual(
            self.publicKey.point.y,
            0x7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299,
        )

    def testSampleMessageSignature(self):
        sig = Ecdsa.sign("sample", self.privateKey)
        # r matches RFC 6979 A.2.5 exactly
        self.assertEqual(sig.r, 0xEFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716)
        # s is low-S normalized: N - 0xF7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8
        self.assertEqual(sig.s, 0x834E36AD29A83BF2BC9385E491D6099C8FDF9D1ED67AA7EA5F51F93782857A9)
        self.assertTrue(Ecdsa.verify("sample", sig, self.publicKey))

    def testTestMessageSignature(self):
        sig = Ecdsa.sign("test", self.privateKey)
        # r matches RFC 6979 A.2.5 exactly
        self.assertEqual(sig.r, 0xF1ABB023518351CD71D881567B1EA663ED3EFCF6C5132B354F28D3B0B7D38367)
        # s already low-S, matches RFC directly
        self.assertEqual(sig.s, 0x019F4113742A2B14BD25926B49C649155F267E60D3814B4C0CC84250E46F0083)
        self.assertTrue(Ecdsa.verify("test", sig, self.publicKey))


class Secp256k1KnownAnswerTest(TestCase):
    """Known-answer tests for secp256k1 with secret=1 (pubkey = generator G)."""

    def setUp(self):
        self.privateKey = PrivateKey(curve=secp256k1, secret=1)
        self.publicKey = self.privateKey.publicKey()

    def testPublicKeyIsGenerator(self):
        self.assertEqual(self.publicKey.point.x, secp256k1.G.x)
        self.assertEqual(self.publicKey.point.y, secp256k1.G.y)

    def testSampleMessageSignature(self):
        sig = Ecdsa.sign("sample", self.privateKey)
        self.assertEqual(sig.r, 0x58DB657BCD631038BEA07B4941172F0167ACA98F12B55E3176BD1C35435D6501)
        self.assertEqual(sig.s, 0x3A78E73D8FF8AB554E13C10F6390D81A882F91945D6275493882676170B53A57)
        self.assertTrue(Ecdsa.verify("sample", sig, self.publicKey))

    def testTestMessageSignature(self):
        sig = Ecdsa.sign("test", self.privateKey)
        self.assertEqual(sig.r, 0x98DF3AAED18D1299109E9732E3015F7E68E5D1FDEAD6924809B410D970A3B0CE)
        self.assertEqual(sig.s, 0x3EF15987C6592379BAAD6392586A382D63952572632FCD951AE75E7471C144C6)
        self.assertTrue(Ecdsa.verify("test", sig, self.publicKey))


class MalleabilityTest(TestCase):

    def testSignAlwaysProducesLowS(self):
        for _ in range(100):
            privateKey = PrivateKey()
            signature = Ecdsa.sign("test message", privateKey)
            self.assertTrue(signature.s <= privateKey.curve.N // 2)

    def testHighSSignatureStillVerifies(self):
        """verify() accepts high-s for OpenSSL compatibility; sign() prevents malleability"""
        privateKey = PrivateKey()
        publicKey = privateKey.publicKey()
        message = "test message"

        signature = Ecdsa.sign(message, privateKey)
        highS = Signature(r=signature.r, s=privateKey.curve.N - signature.s)

        self.assertTrue(Ecdsa.verify(message, signature, publicKey))
        self.assertTrue(Ecdsa.verify(message, highS, publicKey))


class PublicKeyValidationTest(TestCase):

    def testRejectOffCurvePublicKey(self):
        privateKey = PrivateKey()
        publicKey = privateKey.publicKey()
        message = "test message"

        signature = Ecdsa.sign(message, privateKey)

        offCurvePoint = Point(publicKey.point.x, publicKey.point.y + 1)
        offCurveKey = PublicKey(point=offCurvePoint, curve=publicKey.curve)

        self.assertFalse(Ecdsa.verify(message, signature, offCurveKey))

    def testFromStringRejectsOffCurvePoint(self):
        p = PrivateKey().publicKey()
        badY = hexFromInt(p.point.y + 1).zfill(2 * p.curve.length())
        badHex = hexFromInt(p.point.x).zfill(2 * p.curve.length()) + badY
        with self.assertRaises(Exception):
            PublicKey.fromString(badHex, curve=p.curve)

    def testFromStringRejectsInfinityPoint(self):
        zeroHex = "00" * (2 * secp256k1.length())
        with self.assertRaises(Exception):
            PublicKey.fromString(zeroHex, curve=secp256k1)


class ForgeryAttemptTest(TestCase):

    def setUp(self):
        self.privateKey = PrivateKey()
        self.publicKey = self.privateKey.publicKey()
        self.message = "authentic message"
        self.signature = Ecdsa.sign(self.message, self.privateKey)

    def testRejectZeroSignature(self):
        self.assertFalse(Ecdsa.verify(self.message, Signature(0, 0), self.publicKey))

    def testRejectREqualsZero(self):
        self.assertFalse(Ecdsa.verify(self.message, Signature(0, self.signature.s), self.publicKey))

    def testRejectSEqualsZero(self):
        self.assertFalse(Ecdsa.verify(self.message, Signature(self.signature.r, 0), self.publicKey))

    def testRejectREqualsN(self):
        N = self.publicKey.curve.N
        self.assertFalse(Ecdsa.verify(self.message, Signature(N, self.signature.s), self.publicKey))

    def testRejectSEqualsN(self):
        N = self.publicKey.curve.N
        self.assertFalse(Ecdsa.verify(self.message, Signature(self.signature.r, N), self.publicKey))

    def testRejectRExceedsN(self):
        N = self.publicKey.curve.N
        self.assertFalse(Ecdsa.verify(self.message, Signature(N + 1, self.signature.s), self.publicKey))

    def testRejectArbitrarySignature(self):
        self.assertFalse(Ecdsa.verify(self.message, Signature(1, 1), self.publicKey))

    def testRejectBoundarySignature(self):
        N = self.publicKey.curve.N
        self.assertFalse(Ecdsa.verify(self.message, Signature(N - 1, N - 1), self.publicKey))

    def testWrongKeyRejected(self):
        otherKey = PrivateKey().publicKey()
        self.assertFalse(Ecdsa.verify(self.message, self.signature, otherKey))


class Rfc6979Test(TestCase):

    def testDeterministicSignature(self):
        privateKey = PrivateKey()
        message = "test message"

        signature1 = Ecdsa.sign(message, privateKey)
        signature2 = Ecdsa.sign(message, privateKey)

        self.assertEqual(signature1.r, signature2.r)
        self.assertEqual(signature1.s, signature2.s)

    def testDifferentMessagesDifferentSignatures(self):
        privateKey = PrivateKey()

        signature1 = Ecdsa.sign("message 1", privateKey)
        signature2 = Ecdsa.sign("message 2", privateKey)

        self.assertTrue(signature1.r != signature2.r or signature1.s != signature2.s)

    def testDifferentKeysDifferentSignatures(self):
        message = "test message"

        signature1 = Ecdsa.sign(message, PrivateKey())
        signature2 = Ecdsa.sign(message, PrivateKey())

        self.assertTrue(signature1.r != signature2.r or signature1.s != signature2.s)


class EdgeCaseMessageTest(TestCase):

    def setUp(self):
        self.privateKey = PrivateKey()
        self.publicKey = self.privateKey.publicKey()

    def _signAndVerify(self, message):
        sig = Ecdsa.sign(message, self.privateKey)
        self.assertTrue(Ecdsa.verify(message, sig, self.publicKey))
        self.assertFalse(Ecdsa.verify(message + "x", sig, self.publicKey))

    def testEmptyMessage(self):
        self._signAndVerify("")

    def testSingleCharMessage(self):
        self._signAndVerify("a")

    def testUnicodeMessage(self):
        self._signAndVerify("\u00e9\u00e8\u00ea\u00eb")

    def testEmojiMessage(self):
        self._signAndVerify("\U0001f512\U0001f511")

    def testNullByteMessage(self):
        self._signAndVerify("before\x00after")

    def testLongMessage(self):
        self._signAndVerify("a" * 10000)

    def testNewlinesAndWhitespace(self):
        self._signAndVerify("  line1\n\tline2\r\n  ")


class SerializationRoundTripTest(TestCase):

    def setUp(self):
        self.privateKey = PrivateKey()
        self.publicKey = self.privateKey.publicKey()
        self.message = "round-trip test"
        self.signature = Ecdsa.sign(self.message, self.privateKey)

    def testSignatureDerRoundTrip(self):
        der = self.signature.toDer()
        restored = Signature.fromDer(der)
        self.assertEqual(restored.r, self.signature.r)
        self.assertEqual(restored.s, self.signature.s)
        self.assertTrue(Ecdsa.verify(self.message, restored, self.publicKey))

    def testSignatureBase64RoundTrip(self):
        b64 = self.signature.toBase64()
        restored = Signature.fromBase64(b64)
        self.assertEqual(restored.r, self.signature.r)
        self.assertEqual(restored.s, self.signature.s)
        self.assertTrue(Ecdsa.verify(self.message, restored, self.publicKey))

    def testSignatureDerWithRecoveryIdRoundTrip(self):
        der = self.signature.toDer(withRecoveryId=True)
        restored = Signature.fromDer(der, recoveryByte=True)
        self.assertEqual(restored.r, self.signature.r)
        self.assertEqual(restored.s, self.signature.s)
        self.assertEqual(restored.recoveryId, self.signature.recoveryId)

    def testPrivateKeyPemRoundTrip(self):
        pem = self.privateKey.toPem()
        restored = PrivateKey.fromPem(pem)
        self.assertEqual(restored.secret, self.privateKey.secret)
        self.assertEqual(restored.curve.name, self.privateKey.curve.name)

    def testPrivateKeyDerRoundTrip(self):
        der = self.privateKey.toDer()
        restored = PrivateKey.fromDer(der)
        self.assertEqual(restored.secret, self.privateKey.secret)

    def testPublicKeyPemRoundTrip(self):
        pem = self.publicKey.toPem()
        restored = PublicKey.fromPem(pem)
        self.assertEqual(restored.point.x, self.publicKey.point.x)
        self.assertEqual(restored.point.y, self.publicKey.point.y)

    def testPublicKeyCompressedRoundTrip(self):
        compressed = self.publicKey.toCompressed()
        restored = PublicKey.fromCompressed(compressed, curve=self.publicKey.curve)
        self.assertEqual(restored.point.x, self.publicKey.point.x)
        self.assertEqual(restored.point.y, self.publicKey.point.y)
        self.assertTrue(Ecdsa.verify(self.message, self.signature, restored))

    def testPublicKeyCompressedEvenAndOdd(self):
        """Ensure both even-y and odd-y keys round-trip through compression"""
        for _ in range(20):
            pk = PrivateKey()
            pub = pk.publicKey()
            compressed = pub.toCompressed()
            restored = PublicKey.fromCompressed(compressed, curve=pub.curve)
            self.assertEqual(restored.point.x, pub.point.x)
            self.assertEqual(restored.point.y, pub.point.y)

    def testPrime256v1KeyRoundTrip(self):
        pk = PrivateKey(curve=prime256v1)
        pem = pk.toPem()
        restored = PrivateKey.fromPem(pem)
        self.assertEqual(restored.secret, pk.secret)
        self.assertEqual(restored.curve.name, "prime256v1")


class TonelliShanksTest(TestCase):

    def testPrimeCongruent1Mod4(self):
        # P = 17: 17 - 1 = 16 = 2^4, S = 4, exercises full Tonelli-Shanks
        P = 17
        for value in range(1, P):
            if pow(value, (P - 1) // 2, P) == 1:
                root = Math.modularSquareRoot(value, P)
                self.assertEqual((root * root) % P, value)

    def testPrimeCongruent5Mod8(self):
        # P = 13: 13 - 1 = 12 = 3 * 2^2, S = 2
        P = 13
        for value in range(1, P):
            if pow(value, (P - 1) // 2, P) == 1:
                root = Math.modularSquareRoot(value, P)
                self.assertEqual((root * root) % P, value)

    def testPrimeCongruent3Mod4(self):
        # P = 7: fast path (S = 1)
        P = 7
        for value in range(1, P):
            if pow(value, (P - 1) // 2, P) == 1:
                root = Math.modularSquareRoot(value, P)
                self.assertEqual((root * root) % P, value)

    def testZeroValue(self):
        self.assertEqual(Math.modularSquareRoot(0, 17), 0)


class HashTruncationTest(TestCase):

    def testSignVerifyWithSha512(self):
        privateKey = PrivateKey()
        publicKey = privateKey.publicKey()
        message = "test message"

        signature = Ecdsa.sign(message, privateKey, hashfunc=sha512)

        self.assertTrue(Ecdsa.verify(message, signature, publicKey, hashfunc=sha512))
        self.assertFalse(Ecdsa.verify("wrong message", signature, publicKey, hashfunc=sha512))

    def testSha512DeterministicSignature(self):
        privateKey = PrivateKey()
        message = "test message"

        signature1 = Ecdsa.sign(message, privateKey, hashfunc=sha512)
        signature2 = Ecdsa.sign(message, privateKey, hashfunc=sha512)

        self.assertEqual(signature1.r, signature2.r)
        self.assertEqual(signature1.s, signature2.s)

    def testHashMismatchFails(self):
        privateKey = PrivateKey()
        publicKey = privateKey.publicKey()
        message = "test message"

        signature = Ecdsa.sign(message, privateKey, hashfunc=sha256)
        self.assertFalse(Ecdsa.verify(message, signature, publicKey, hashfunc=sha512))


class Prime256v1SecurityTest(TestCase):

    def testSignVerify(self):
        privateKey = PrivateKey(curve=prime256v1)
        publicKey = privateKey.publicKey()
        message = "test message"

        signature = Ecdsa.sign(message, privateKey)

        self.assertTrue(signature.s <= prime256v1.N // 2)
        self.assertTrue(Ecdsa.verify(message, signature, publicKey))

    def testDeterministicSignature(self):
        privateKey = PrivateKey(curve=prime256v1)
        message = "test message"

        signature1 = Ecdsa.sign(message, privateKey)
        signature2 = Ecdsa.sign(message, privateKey)

        self.assertEqual(signature1.r, signature2.r)
        self.assertEqual(signature1.s, signature2.s)

    def testWrongCurveKeyFails(self):
        """A signature made with secp256k1 should not verify with a prime256v1 key"""
        k1Key = PrivateKey(curve=secp256k1)
        p256Key = PrivateKey(curve=prime256v1)
        message = "cross-curve test"

        sig = Ecdsa.sign(message, k1Key)
        self.assertFalse(Ecdsa.verify(message, sig, p256Key.publicKey()))
