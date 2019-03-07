

class File:

    @classmethod
    def read(cls, path):
        return open(path, 'rb').read()
