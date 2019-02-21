

class File:

    @classmethod
    def read(cls, path):
        return open(path).read()
