from unittest.case import TestCase
from ellipticcurve import Ecdsa, Signature, PublicKey, PrivateKey


class RandomTest(TestCase):

    def testMany(self):
        for _ in range(1000):
            privateKey1 = PrivateKey()
            publicKey1 = privateKey1.publicKey()

            privateKeyPem = privateKey1.toPem()
            publicKeyPem = publicKey1.toPem()

            privateKey2 = PrivateKey.fromPem(privateKeyPem)
            publicKey2 = PublicKey.fromPem(publicKeyPem)

            message = "test"

            signatureBase64 = Ecdsa.sign(message=message, privateKey=privateKey2).toBase64()
            signature = Signature.fromBase64(signatureBase64)

            self.assertTrue(Ecdsa.verify(message=message, signature=signature, publicKey=publicKey2))
