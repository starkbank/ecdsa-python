# coding=utf-8

from unittest.case import TestCase
from ellipticcurve.privateKey import PrivateKey
from ellipticcurve.utils.compatibility import *


class PrivateKeyTest(TestCase):

    def testPemConversion(self):
        privateKey1 = PrivateKey()
        pem = privateKey1.toPem()
        privateKey2 = PrivateKey.fromPem(pem)
        self.assertEqual(privateKey1.secret, privateKey2.secret)
        self.assertEqual(privateKey1.curve, privateKey2.curve)

    def testDerConversion(self):
        privateKey1 = PrivateKey()
        der = privateKey1.toDer()
        privateKey2 = PrivateKey.fromDer(toBytes(der))
        self.assertEqual(privateKey1.secret, privateKey2.secret)
        self.assertEqual(privateKey1.curve, privateKey2.curve)

    def testStringConversion(self):
        privateKey1 = PrivateKey()
        string = privateKey1.toString()
        privateKey2 = PrivateKey.fromString(toBytes(string))
        self.assertEqual(privateKey1.secret, privateKey2.secret)
        self.assertEqual(privateKey1.curve, privateKey2.curve)