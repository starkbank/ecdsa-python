## Lightweight and Fast Pure Python ECDSA

### Overview

We try other Python libraries such as [python-ecdsa], [fast-ecdsa] and others less famous ones, but we don't find what suit us. The Fist one is based on pure Python, but it's too slow. The second one mixed Python and C, it's really fast, but we were unable to use it in our current infrastructure that required pure Python code.

[python-ecdsa]: https://github.com/warner/python-ecdsa
[fast-ecdsa]: https://github.com/AntonKueltz/fastecdsa

For this reason, we decide to create something simple, compatible with `OpenSSL` and fast using some eleghant math as Jacobian Coordenates to speed up the ECDSA.

### Curves

We current support `secp256k1`but it's super easy to add more curves to the project.

### Speed

We run the test on a MAC Pro i7 2017. We run the each library 100 times and get the average time dispaly bellow:

| Library          | sign          | verify  |
| ---------------- |:-------------:| -------:|
| [python-ecdsa]   | 121.3ms       | 65.1ms  |
| [fast-ecdsa]     | 0.1ms         |  0.2ms  |
| ellipctic-curve  | 4.1ms         |  8.2ms  |

So pure Python can not compete with libraries with C, but it's `6x faster` to verify and `23x faster` to sign then other pure python libraries.

```python
# Generate Keys
privateKey = PrivateKey()
publicKey = privateKey.publicKey()
message = "My test message"

# Generate Signature
signature = Ecsda.sign(message, privateKey)

# Verify if signature is valid
print Ecsda.verify(message, signature, publicKey)
```

### OpenSSl

This library is compatible with OpenSSL, so you can use it to generate keys:

```
openssl ecparam -name secp256k1 -genkey -out privateKey.pem
openssl ec -in privateKey.pem -pubout -out publicKey.pem
```

Create a message.txt file and sign it:

```
openssl dgst -sha256 -sign privateKey.pem -out signature.binary message.txt
```

It's time to verify:

```python
publicKeyPem = open("publicKey.pem").read()
signatureBin = open("signature.binary").read()
message = open("message.txt").read()

publicKey = PublicKey.fromPem(publicKeyPem)
signature = Signature.decode(signatureBin)
print Ecdsa.verify(message, signature, publicKey)
```