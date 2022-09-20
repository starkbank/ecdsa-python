from unittest.case import TestCase
from ellipticcurve import curve, PublicKey, Signature, Ecdsa, PrivateKey


class CurveTest(TestCase):

    def testSupportedCurve(self):
        newCurve = curve.CurveFp(
            name="secp256k1",
            A=0x0000000000000000000000000000000000000000000000000000000000000000,
            B=0x0000000000000000000000000000000000000000000000000000000000000007,
            P=0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f,
            N=0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141,
            Gx=0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798,
            Gy=0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8,
            oid=[1, 3, 132, 0, 10]
        )
        privateKey1 = PrivateKey(curve=newCurve)
        publicKey1 = privateKey1.publicKey()

        privateKeyPem = privateKey1.toPem()
        publicKeyPem = publicKey1.toPem()

        privateKey2 = PrivateKey.fromPem(privateKeyPem)
        publicKey2 = PublicKey.fromPem(publicKeyPem)

        message = "test"

        signatureBase64 = Ecdsa.sign(message=message, privateKey=privateKey2).toBase64()
        signature = Signature.fromBase64(signatureBase64)

        self.assertTrue(Ecdsa.verify(message=message, signature=signature, publicKey=publicKey2))

    def testAddNewCurve(self):
        newCurve = curve.CurveFp(
            name="frp256v1",
            A=0xf1fd178c0b3ad58f10126de8ce42435b3961adbcabc8ca6de8fcf353d86e9c00,
            B=0xee353fca5428a9300d4aba754a44c00fdfec0c9ae4b1a1803075ed967b7bb73f,
            P=0xf1fd178c0b3ad58f10126de8ce42435b3961adbcabc8ca6de8fcf353d86e9c03,
            N=0xf1fd178c0b3ad58f10126de8ce42435b53dc67e140d2bf941ffdd459c6d655e1,
            Gx=0xb6b3d4c356c139eb31183d4749d423958c27d2dcaf98b70164c97a2dd98f5cff,
            Gy=0x6142e0f7c8b204911f9271f0f3ecef8c2701c307e8e4c9e183115a1554062cfb,
            oid=[1, 2, 250, 1, 223, 101, 256, 1]
        )
        curve.add(newCurve)
        privateKey1 = PrivateKey(curve=newCurve)
        publicKey1 = privateKey1.publicKey()

        privateKeyPem = privateKey1.toPem()
        publicKeyPem = publicKey1.toPem()

        privateKey2 = PrivateKey.fromPem(privateKeyPem)
        publicKey2 = PublicKey.fromPem(publicKeyPem)

        message = "test"

        signatureBase64 = Ecdsa.sign(message=message, privateKey=privateKey2).toBase64()
        signature = Signature.fromBase64(signatureBase64)

        self.assertTrue(Ecdsa.verify(message=message, signature=signature, publicKey=publicKey2))

    def testUnsupportedCurve(self):
        newCurve = curve.CurveFp(
            name="brainpoolP256t1",
            A=0xa9fb57dba1eea9bc3e660a909d838d726e3bf623d52620282013481d1f6e5374,
            B=0x662c61c430d84ea4fe66a7733d0b76b7bf93ebc4af2f49256ae58101fee92b04,
            P=0xa9fb57dba1eea9bc3e660a909d838d726e3bf623d52620282013481d1f6e5377,
            N=0xa9fb57dba1eea9bc3e660a909d838d718c397aa3b561a6f7901e0e82974856a7,
            Gx=0xa3e8eb3cc1cfe7b7732213b23a656149afa142c47aafbc2b79a191562e1305f4,
            Gy=0x2d996c823439c56d7f7b22e14644417e69bcb6de39d027001dabe8f35b25c9be,
            oid=[1, 3, 36, 3, 3, 2, 8, 1, 1, 8]
        )

        privateKeyPem = PrivateKey(curve=newCurve).toPem()
        publicKeyPem = PrivateKey(curve=newCurve).publicKey().toPem()

        with self.assertRaises(Exception) as context:
            privateKey = PrivateKey.fromPem(privateKeyPem)
        self.assertTrue('Unknown curve' in str(context.exception))

        with self.assertRaises(Exception) as context:
            publicKey = PublicKey.fromPem(publicKeyPem)
        self.assertTrue('Unknown curve' in str(context.exception))


