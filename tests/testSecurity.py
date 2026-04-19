from unittest.case import TestCase
from hashlib import sha256, sha512
from ellipticcurve import Ecdsa, PrivateKey, PublicKey, Signature
from ellipticcurve.curve import secp256k1, prime256v1
from ellipticcurve.point import Point
from ellipticcurve.math import Math
from ellipticcurve.utils.binary import hexFromInt


class Prime256v1PublicKeyDerivationTest(TestCase):
    """RFC 6979 A.2.5 public key derivation. Signatures are hedged, so r/s
    no longer match fixed test vectors, but pubkey derivation is unchanged."""

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

    def testSampleMessageRoundTrip(self):
        sig = Ecdsa.sign("sample", self.privateKey)
        self.assertTrue(sig.s <= prime256v1.N // 2)
        self.assertTrue(Ecdsa.verify("sample", sig, self.publicKey))

    def testTestMessageRoundTrip(self):
        sig = Ecdsa.sign("test", self.privateKey)
        self.assertTrue(sig.s <= prime256v1.N // 2)
        self.assertTrue(Ecdsa.verify("test", sig, self.publicKey))


class Secp256k1PublicKeyDerivationTest(TestCase):
    """secp256k1 with secret=1 (pubkey = generator G)."""

    def setUp(self):
        self.privateKey = PrivateKey(curve=secp256k1, secret=1)
        self.publicKey = self.privateKey.publicKey()

    def testPublicKeyIsGenerator(self):
        self.assertEqual(self.publicKey.point.x, secp256k1.G.x)
        self.assertEqual(self.publicKey.point.y, secp256k1.G.y)

    def testSampleMessageRoundTrip(self):
        sig = Ecdsa.sign("sample", self.privateKey)
        self.assertTrue(Ecdsa.verify("sample", sig, self.publicKey))

    def testTestMessageRoundTrip(self):
        sig = Ecdsa.sign("test", self.privateKey)
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


class HedgedSignatureTest(TestCase):

    def testSameInputsProduceDifferentSignatures(self):
        privateKey = PrivateKey()
        message = "test message"

        signature1 = Ecdsa.sign(message, privateKey)
        signature2 = Ecdsa.sign(message, privateKey)

        self.assertTrue(signature1.r != signature2.r or signature1.s != signature2.s)

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

    def testSha512SignaturesAreHedged(self):
        privateKey = PrivateKey()
        message = "test message"

        signature1 = Ecdsa.sign(message, privateKey, hashfunc=sha512)
        signature2 = Ecdsa.sign(message, privateKey, hashfunc=sha512)

        self.assertTrue(signature1.r != signature2.r or signature1.s != signature2.s)

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

    def testSignaturesAreHedged(self):
        privateKey = PrivateKey(curve=prime256v1)
        message = "test message"

        signature1 = Ecdsa.sign(message, privateKey)
        signature2 = Ecdsa.sign(message, privateKey)

        self.assertTrue(signature1.r != signature2.r or signature1.s != signature2.s)

    def testWrongCurveKeyFails(self):
        """A signature made with secp256k1 should not verify with a prime256v1 key"""
        k1Key = PrivateKey(curve=secp256k1)
        p256Key = PrivateKey(curve=prime256v1)
        message = "cross-curve test"

        sig = Ecdsa.sign(message, k1Key)
        self.assertFalse(Ecdsa.verify(message, sig, p256Key.publicKey()))
