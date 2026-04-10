import time
import sys
from ellipticcurve import Ecdsa, PrivateKey


ROUNDS = 100


def benchmark():
    privateKey = PrivateKey()
    publicKey = privateKey.publicKey()
    message = "This is a benchmark test message"

    # Warmup
    sig = Ecdsa.sign(message, privateKey)
    Ecdsa.verify(message, sig, publicKey)

    # Benchmark sign
    start = time.time()
    for _ in range(ROUNDS):
        sig = Ecdsa.sign(message, privateKey)
    signTime = (time.time() - start) / ROUNDS * 1000

    # Benchmark verify
    start = time.time()
    for _ in range(ROUNDS):
        Ecdsa.verify(message, sig, publicKey)
    verifyTime = (time.time() - start) / ROUNDS * 1000

    print("")
    print("starkbank-ecdsa benchmark ({rounds} rounds)".format(rounds=ROUNDS))
    print("---------------------------------------")
    print("sign:    {time:.1f}ms".format(time=signTime))
    print("verify:  {time:.1f}ms".format(time=verifyTime))
    print("")


if __name__ == "__main__":
    benchmark()
