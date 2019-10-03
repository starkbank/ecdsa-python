# coding=utf-8

from unittest.case import TestCase
from ellipticcurve.privateKey import PrivateKey
from ellipticcurve.publicKey import PublicKey
from ellipticcurve.utils.compatibility import *


class PublicKeyTest(TestCase):

    def testPemConversion(self):
        privateKey = PrivateKey()
        publicKey1 = privateKey.publicKey()
        pem = publicKey1.toPem()
        publicKey2 = PublicKey.fromPem(pem)
        self.assertEqual(publicKey1.point.x, publicKey2.point.x)
        self.assertEqual(publicKey1.point.y, publicKey2.point.y)
        self.assertEqual(publicKey1.curve, publicKey2.curve)

    def testDerConversion(self):
        privateKey = PrivateKey()
        publicKey1 = privateKey.publicKey()
        der = publicKey1.toDer()
        publicKey2 = PublicKey.fromDer(toBytes(der))
        self.assertEqual(publicKey1.point.x, publicKey2.point.x)
        self.assertEqual(publicKey1.point.y, publicKey2.point.y)
        self.assertEqual(publicKey1.curve, publicKey2.curve)

    def testStringConversion(self):
        privateKey = PrivateKey()
        publicKey1 = privateKey.publicKey()
        string = publicKey1.toString()
        publicKey2 = PublicKey.fromString(toBytes(string))
        self.assertEqual(publicKey1.point.x, publicKey2.point.x)
        self.assertEqual(publicKey1.point.y, publicKey2.point.y)
        self.assertEqual(publicKey1.curve, publicKey2.curve)
