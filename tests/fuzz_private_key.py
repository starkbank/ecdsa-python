import sys
import atheris

with atheris.instrument_imports():
    from ellipticcurve import Ecdsa, Signature, PublicKey, PrivateKey


@atheris.instrument_func
def TestOneInput(input_bytes):
    fdp = atheris.FuzzedDataProvider(input_bytes)

    privateKey1 = PrivateKey()
    publicKey1 = privateKey1.publicKey()

    privateKeyPem = privateKey1.toPem()
    publicKeyPem = publicKey1.toPem()

    privateKey2 = PrivateKey.fromPem(privateKeyPem)
    publicKey2 = PublicKey.fromPem(publicKeyPem)

    message = fdp.ConsumeUnicode(sys.maxsize)

    signatureBase64 = Ecdsa.sign(message=message,
                                 privateKey=privateKey2).toBase64()

    signature = Signature.fromBase64(signatureBase64)
    assert(Ecdsa.verify(message=message, signature=signature, publicKey=publicKey2))


def main():
    atheris.Setup(sys.argv, TestOneInput, enable_python_coverage=True)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
