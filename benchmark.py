import time
from hashlib import sha256
from ellipticcurve import Ecdsa, PrivateKey


ROUNDS = 500
MESSAGE = "This is a benchmark test message"


def benchmarkStarkbank():
    privateKey = PrivateKey()
    publicKey = privateKey.publicKey()

    sig = Ecdsa.sign(MESSAGE, privateKey)
    Ecdsa.verify(MESSAGE, sig, publicKey)

    start = time.time()
    for _ in range(ROUNDS):
        sig = Ecdsa.sign(MESSAGE, privateKey)
    signTime = (time.time() - start) / ROUNDS * 1000

    start = time.time()
    for _ in range(ROUNDS):
        Ecdsa.verify(MESSAGE, sig, publicKey)
    verifyTime = (time.time() - start) / ROUNDS * 1000

    return signTime, verifyTime


def benchmarkPythonEcdsa():
    try:
        from ecdsa import SigningKey, SECP256k1
    except ImportError:
        return None, None

    sk = SigningKey.generate(curve=SECP256k1)
    vk = sk.verifying_key
    data = MESSAGE.encode()

    sig = sk.sign_deterministic(data, hashfunc=sha256)
    vk.verify(sig, data, hashfunc=sha256)

    start = time.time()
    for _ in range(ROUNDS):
        sig = sk.sign_deterministic(data, hashfunc=sha256)
    signTime = (time.time() - start) / ROUNDS * 1000

    start = time.time()
    for _ in range(ROUNDS):
        vk.verify(sig, data, hashfunc=sha256)
    verifyTime = (time.time() - start) / ROUNDS * 1000

    return signTime, verifyTime


def benchmarkFastEcdsa():
    try:
        from fastecdsa import curve, ecdsa, keys
    except ImportError:
        return None, None

    privateKey, publicKey = keys.gen_keypair(curve.secp256k1)

    r, s = ecdsa.sign(MESSAGE, privateKey, curve=curve.secp256k1)
    ecdsa.verify((r, s), MESSAGE, publicKey, curve=curve.secp256k1)

    start = time.time()
    for _ in range(ROUNDS):
        r, s = ecdsa.sign(MESSAGE, privateKey, curve=curve.secp256k1)
    signTime = (time.time() - start) / ROUNDS * 1000

    start = time.time()
    for _ in range(ROUNDS):
        ecdsa.verify((r, s), MESSAGE, publicKey, curve=curve.secp256k1)
    verifyTime = (time.time() - start) / ROUNDS * 1000

    return signTime, verifyTime


def formatTime(ms):
    return "n/a" if ms is None else "{:.1f}ms".format(ms)


def main():
    results = [
        ("python-ecdsa", benchmarkPythonEcdsa()),
        ("fast-ecdsa", benchmarkFastEcdsa()),
        ("starkbank-ecdsa", benchmarkStarkbank()),
    ]

    print("")
    print("ECDSA benchmark on secp256k1 ({} rounds)".format(ROUNDS))
    print("-" * 48)
    print("{:<20} {:>12} {:>12}".format("library", "sign", "verify"))
    print("-" * 48)
    for name, (signMs, verifyMs) in results:
        print("{:<20} {:>12} {:>12}".format(name, formatTime(signMs), formatTime(verifyMs)))
    print("")


if __name__ == "__main__":
    main()
