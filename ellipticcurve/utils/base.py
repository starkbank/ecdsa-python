from base64 import b64encode, b64decode


class Base64:

    @classmethod
    def decode(cls, string):
        return b64decode(string)

    @classmethod
    def encode(cls, string):
        return b64encode(string)
