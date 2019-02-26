## A lightweight and fast pure Python ECDSA

### Overview

We tried other Python libraries such as [python-ecdsa], [fast-ecdsa] and others less famous ones, but we didn't find anything that suit our needs. The fist one was pure Python, but it was too slow. The second one mixed Python and C and it was really fast, but we were unable to use it in our current infrastructure that required pure Python code.

[python-ecdsa]: https://github.com/warner/python-ecdsa
[fast-ecdsa]: https://github.com/AntonKueltz/fastecdsa

For this reason, we decided to create something simple, compatible with OpenSSL and fast using some elegant math as Jacobian Coordinates to speed up the ECDSA. Starkbank-EDCSA is fully compatible with Python2 and Python3.

### Curves

We currently support `secp256k1`, but it's super easy to add more curves to the project. Just add them on `curve.py`

### Speed

We ran a test on a MAC Pro i7 2017. We ran the library 100 times and got the average time displayed bellow:

| Library            | sign          | verify  |
| ------------------ |:-------------:| -------:|
| [python-ecdsa]     |   121.3ms     | 65.1ms  |
| [fast-ecdsa]       |     0.1ms     |  0.2ms  |
| starkbank-ecdsa    |     4.1ms     |  7.8ms  |

So our pure Python code cannot compete with C based libraries, but it's `6x faster` to verify and `23x faster` to sign then other pure Python libraries.

### Sample Code

How to use it:

```python
from ellipticcurve.ecdsa import Ecdsa
from ellipticcurve.privateKey import PrivateKey

# Generate Keys
privateKey = PrivateKey()
publicKey = privateKey.publicKey()

message = u"My test message"

# Generate Signature
signature = Ecdsa.sign(message, privateKey)

# Verify if signature is valid
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

It's time to verify:

```python
from ellipticcurve.ecdsa import Ecdsa
from ellipticcurve.signature import Signature
from ellipticcurve.publicKey import PublicKey
from ellipticcurve.utils.file import File

publicKeyPem = File.read("publicKey.pem")
signatureDer = File.read("signatureDer.txt")
message = File.read("message.txt")

publicKeyPem = open("publicKey.pem").read()

publicKey = PublicKey.fromPem(publicKeyPem)
signature = Signature.fromDer(signatureDer)

print(Ecdsa.verify(message, signature, publicKey))
```

You can also verify it on terminal:

```
openssl dgst -sha256 -verify publicKey.pem -signature signatureDer.txt message.txt
```

NOTE: If you want to create a Digital Signature to use in the [Stark Bank], you need to convert the binary signature to base64.

```
openssl base64 -in signatureDer.txt -out signatureBase64.txt
```

With this library, you can do it:

```python
from ellipticcurve.signature import Signature
from ellipticcurve.utils.file import File
signatureDer = File.read("signatureDer.txt")

signature = Signature.fromDer(signatureDer)

print(signature.toBase64())
```

[Stark Bank]: https://starkbank.com

### How to install

```
pip install starkbank-ecdsa
```

### Run all unit tests

```
python3 -m unittest discover
python2 -m unittest discover
```