## A lightweight and fast pure Python ECDSA

### Overview

We tried other Python libraries such as [python-ecdsa], [fast-ecdsa] and other less famous ones, but we didn't find anything that suited our needs. The first one was pure Python, but it was too slow. The second one mixed Python and C and it was really fast, but we were unable to use it in our current infrastructure, which required pure Python code.

For this reason, we decided to create something simple, compatible with OpenSSL and fast using elegant math such as Jacobian Coordinates to speed up the ECDSA. Starkbank-ECDSA is fully compatible with Python 2.7 and Python 3.

### Security

starkbank-ecdsa includes the following security features:

- **Hedged RFC 6979 nonces**: Deterministic k derivation with fresh random entropy mixed into K-init (RFC 6979 §3.6), eliminating the catastrophic risk of nonce reuse that leaks private keys while preserving protection even if the RNG fails
- **Low-S signature normalization**: Prevents signature malleability (BIP-62)
- **Public key on-curve validation**: Blocks invalid-curve attacks during verification
- **Montgomery ladder scalar multiplication**: Constant-operation point multiplication to mitigate timing side channels
- **Hash truncation**: Correctly handles hash functions larger than the curve order (e.g. SHA-512 with secp256k1)
- **Extended Euclidean modular inverse**: Implemented in pure Python for portability (Python 2.7+ and 3.x); transparently uses the C-level `pow(x, -1, n)` fast path on CPython 3.8+ for a roughly order-of-magnitude speedup over Fermat's little theorem on 256-bit operands

### Installation

To install StarkBank`s ECDSA-Python, run:

```sh
pip install starkbank-ecdsa
```

### Curves

We currently support `secp256k1` and `prime256v1` (P-256), but you can add more curves to the project. You just need to use the curve.add() function.

### Speed

We ran a test on an Apple Silicon Mac with Python 3.14. The libraries were run 500 times on secp256k1 with SHA-256 and deterministic (RFC 6979) nonces, and the averages displayed below were obtained:

| Library         |  sign  | verify |
|-----------------|:------:|:------:|
| [python-ecdsa]  | ~1.0ms | ~3.6ms |
| [fast-ecdsa]    | ~1.0ms | ~1.3ms |
| starkbank-ecdsa | ~0.6ms | ~1.7ms |

Our pure Python code cannot compete with C-based libraries backed by GMP's hand-tuned assembly, but it matches the fastest pure-Python implementation on signing and is roughly `30%` faster on verification.

Performance is driven by Jacobian coordinates, a branch-balanced Montgomery ladder for variable-base scalar multiplication, a precomputed affine table of powers-of-two multiples of the generator (`[G, 2G, 4G, …, 2ⁿG]`) combined with a width-2 NAF of the scalar to eliminate doublings during signing, a mixed affine+Jacobian addition fast path, curve-specific shortcuts in point doubling (A=0 for secp256k1, A=-3 for prime256v1), the secp256k1 GLV endomorphism to split 256-bit scalars into two ~128-bit halves for a 4-scalar simultaneous multi-exponentiation during verification, Shamir's trick with Joint Sparse Form as the fallback path for curves without an efficient endomorphism, and the extended Euclidean algorithm for modular inversion.

### Sample Code

How to sign a json message for [Stark Bank]:

```python
from json import dumps
from ellipticcurve.ecdsa import Ecdsa
from ellipticcurve.privateKey import PrivateKey


# Generate privateKey from PEM string
privateKey = PrivateKey.fromPem("""
    -----BEGIN EC PARAMETERS-----
    BgUrgQQACg==
    -----END EC PARAMETERS-----
    -----BEGIN EC PRIVATE KEY-----
    MHQCAQEEIODvZuS34wFbt0X53+P5EnSj6tMjfVK01dD1dgDH02RzoAcGBSuBBAAK
    oUQDQgAE/nvHu/SQQaos9TUljQsUuKI15Zr5SabPrbwtbfT/408rkVVzq8vAisbB
    RmpeRREXj5aog/Mq8RrdYy75W9q/Ig==
    -----END EC PRIVATE KEY-----
""")

# Create message from json
message = dumps({
    "transfers": [
        {
            "amount": 100000000,
            "taxId": "594.739.480-42",
            "name": "Daenerys Targaryen Stormborn",
            "bankCode": "341",
            "branchCode": "2201",
            "accountNumber": "76543-8",
            "tags": ["daenerys", "targaryen", "transfer-1-external-id"]
        }
    ]
})

signature = Ecdsa.sign(message, privateKey)

# Generate Signature in base64. This result can be sent to Stark Bank in the request header as the Digital-Signature parameter.
print(signature.toBase64())

# To double check if the message matches the signature, do this:
publicKey = privateKey.publicKey()

print(Ecdsa.verify(message, signature, publicKey))

```

Simple use:

```python
from ellipticcurve.ecdsa import Ecdsa
from ellipticcurve.privateKey import PrivateKey


# Generate new Keys
privateKey = PrivateKey()
publicKey = privateKey.publicKey()

message = "My test message"

# Generate Signature
signature = Ecdsa.sign(message, privateKey)

# To verify if the signature is valid
print(Ecdsa.verify(message, signature, publicKey))

```

How to add more curves:

```python
from ellipticcurve import curve, PrivateKey, PublicKey

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

publicKeyPem = """-----BEGIN PUBLIC KEY-----
MFswFQYHKoZIzj0CAQYKKoF6AYFfZYIAAQNCAATeEFFYiQL+HmDYTf+QDmvQmWGD
dRJPqLj11do8okvkSxq2lwB6Ct4aITMlCyg3f1msafc/ROSN/Vgj69bDhZK6
-----END PUBLIC KEY-----"""

publicKey = PublicKey.fromPem(publicKeyPem)

print(publicKey.toPem())
```

How to generate compressed public key:

```python
from ellipticcurve import PrivateKey, PublicKey

privateKey = PrivateKey()
publicKey = privateKey.publicKey()
compressedPublicKey = publicKey.toCompressed()

print(compressedPublicKey)
```

How to recover a compressed public key:

```python
from ellipticcurve import PrivateKey, PublicKey

compressedPublicKey = "0252972572d465d016d4c501887b8df303eee3ed602c056b1eb09260dfa0da0ab2"
publicKey = PublicKey.fromCompressed(compressedPublicKey)

print(publicKey.toPem())
```

### OpenSSL

This library is compatible with OpenSSL, so you can use it to generate keys:

```
openssl ecparam -name secp256k1 -genkey -out privateKey.pem
openssl ec -in privateKey.pem -pubout -out publicKey.pem
```

Create a message.txt file and sign it:

```
openssl dgst -sha256 -sign privateKey.pem -out signatureDer.txt message.txt
```

To verify, do this:

```python
from ellipticcurve.ecdsa import Ecdsa
from ellipticcurve.signature import Signature
from ellipticcurve.publicKey import PublicKey
from ellipticcurve.utils.file import File


publicKeyPem = File.read("publicKey.pem")
signatureDer = File.read("signatureDer.txt", "rb")
message = File.read("message.txt")

publicKey = PublicKey.fromPem(publicKeyPem)
signature = Signature.fromDer(signatureDer)

print(Ecdsa.verify(message, signature, publicKey))

```

You can also verify it on terminal:

```
openssl dgst -sha256 -verify publicKey.pem -signature signatureDer.txt message.txt
```

NOTE: If you want to create a Digital Signature to use with [Stark Bank], you need to convert the binary signature to base64.

```
openssl base64 -in signatureDer.txt -out signatureBase64.txt
```

You can do the same with this library:
 
```python
from ellipticcurve.signature import Signature
from ellipticcurve.utils.file import File


signatureDer = File.read("signatureDer.txt", "rb")

signature = Signature.fromDer(signatureDer)

print(signature.toBase64())
```

### Run unit tests

```
python3 -m unittest discover
```

### Run benchmark

```
python3 benchmark.py
```


[python-ecdsa]: https://github.com/tlsfuzzer/python-ecdsa
[fast-ecdsa]: https://github.com/AntonKueltz/fastecdsa
[Stark Bank]: https://starkbank.com
