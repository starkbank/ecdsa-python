## A lightweight and fast pure Python ECDSA

### Overview

We tried other Python libraries such as [python-ecdsa], [fast-ecdsa] and other less famous ones, but we didn't find anything that suited our needs. The first one was pure Python, but it was too slow. The second one mixed Python and C and it was really fast, but we were unable to use it in our current infrastructure, which required pure Python code.

For this reason, we decided to create something simple, compatible with OpenSSL and fast using elegant math such as Jacobian Coordinates to speed up the ECDSA. Starkbank-ECDSA is fully compatible with Python2 and Python3.

### Installation

To install StarkBank`s ECDSA-Python, run:

```sh
pip install starkbank-ecdsa
```

### Curves

We currently support `secp256k1`, but it's super easy to add more curves to the project. Just add them on `curve.py`

### Speed

We ran a test on a MAC Pro i7 2017. The libraries were run 100 times and the averages displayed bellow were obtained:

| Library            | sign          | verify  |
| ------------------ |:-------------:| -------:|
| [python-ecdsa]     |   121.3ms     | 65.1ms  |
| [fast-ecdsa]       |     0.1ms     |  0.2ms  |
| starkbank-ecdsa    |     4.1ms     |  7.8ms  |

Our pure Python code cannot compete with C based libraries, but it's `6x faster` to verify and `23x faster` to sign than other pure Python libraries.

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
python2 -m unittest discover
```


[python-ecdsa]: https://github.com/warner/python-ecdsa
[fast-ecdsa]: https://github.com/AntonKueltz/fastecdsa
[Stark Bank]: https://starkbank.com
