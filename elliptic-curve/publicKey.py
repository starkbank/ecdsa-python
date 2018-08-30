

class PublicKey:

    def __init__(self, x, y, curve):
        self.x = x
        self.y = y
        self.curve = curve

    def toString(self, compressed=True):
        return {
            True:  "020{}".format(str(hex(self.x))[2:-1]),
            False: "040{}{}".format(str(hex(self.x))[2:-1], str(hex(self.y))[2:-1])
        }.get(compressed)