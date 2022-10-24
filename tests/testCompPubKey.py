from unittest.case import TestCase
from ellipticcurve import PrivateKey, PublicKey


class CompPubKeyTest(TestCase):

    def testBatch(self):
        for _ in range(1000):
            privateKey = PrivateKey()
            publicKey = privateKey.publicKey()
            publicKeyString = publicKey.toCompressed()

            recoveredPublicKey = PublicKey.fromCompressed(publicKeyString, publicKey.curve)

            self.assertEqual(publicKey.point.x, recoveredPublicKey.point.x)
            self.assertEqual(publicKey.point.y, recoveredPublicKey.point.y)

    def testFromCompressedEven(self):
        publicKeyCompressed = "0252972572d465d016d4c501887b8df303eee3ed602c056b1eb09260dfa0da0ab2"
        publicKey = PublicKey.fromCompressed(publicKeyCompressed)
        self.assertEqual(publicKey.toPem(), "\n-----BEGIN PUBLIC KEY-----\nMFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEUpclctRl0BbUxQGIe43zA+7j7WAsBWse\nsJJg36DaCrKIdC9NyX2e22/ZRrq8AC/fsG8myvEXuUBe15J1dj/bHA==\n-----END PUBLIC KEY-----\n")

    def testFromCompressedOdd(self):
        publicKeyCompressed = "0318ed2e1ec629e2d3dae7be1103d4f911c24e0c80e70038f5eb5548245c475f50"
        publicKey = PublicKey.fromCompressed(publicKeyCompressed)
        self.assertEqual(publicKey.toPem(), "\n-----BEGIN PUBLIC KEY-----\nMFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEGO0uHsYp4tPa574RA9T5EcJODIDnADj1\n61VIJFxHX1BMIg0B4cpBnLG6SzOTthXpndIKpr8HEHj3D9lJAI50EQ==\n-----END PUBLIC KEY-----\n")

    def testToCompressedEven(self):
        publicKey = PublicKey.fromPem("-----BEGIN PUBLIC KEY-----\nMFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEUpclctRl0BbUxQGIe43zA+7j7WAsBWse\nsJJg36DaCrKIdC9NyX2e22/ZRrq8AC/fsG8myvEXuUBe15J1dj/bHA==\n-----END PUBLIC KEY-----")
        publicKeyCompressed = publicKey.toCompressed()
        self.assertEqual(publicKeyCompressed, "0252972572d465d016d4c501887b8df303eee3ed602c056b1eb09260dfa0da0ab2")

    def testToCompressedOdd(self):
        publicKey = PublicKey.fromPem("-----BEGIN PUBLIC KEY-----\nMFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEGO0uHsYp4tPa574RA9T5EcJODIDnADj1\n61VIJFxHX1BMIg0B4cpBnLG6SzOTthXpndIKpr8HEHj3D9lJAI50EQ==\n-----END PUBLIC KEY-----")
        publicKeyCompressed = publicKey.toCompressed()
        self.assertEqual(publicKeyCompressed, "0318ed2e1ec629e2d3dae7be1103d4f911c24e0c80e70038f5eb5548245c475f50")
