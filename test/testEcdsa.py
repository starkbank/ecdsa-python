from unittest.case import TestCase
from ellipticcurve.ecdsa import Ecdsa
from ellipticcurve.privateKey import PrivateKey


class EcdsaTest(TestCase):

    def testVerifyRightMessage(self):
        privateKey = PrivateKey()
        publicKey = privateKey.publicKey()

        message = "This is the right message"

        signature = Ecdsa.sign(message, privateKey)

        self.assertTrue(Ecdsa.verify(message, signature, publicKey))

    def testVerifyWrongMessage(self):
        privateKey = PrivateKey()
        publicKey = privateKey.publicKey()

        message1 = "This is the right message"
        message2 = "This is the wrong message"

        signature = Ecdsa.sign(message1, privateKey)

        self.assertFalse(Ecdsa.verify(message2, signature, publicKey))
