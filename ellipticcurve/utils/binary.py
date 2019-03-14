from .compatibility import *


class BinaryAscii:

    @classmethod
    def hexFromBinary(cls, data):
        """
        Return the hexadecimal representation of the binary data. Every byte of data is converted into the
        corresponding 2-digit hex representation. The resulting string is therefore twice as long as the length of data.

        :param data: binary
        :return: hexadecimal string
        """
        return safeHexFromBinary(data)

    @classmethod
    def binaryFromHex(cls, data):
        """
        Return the binary data represented by the hexadecimal string hexstr. This function is the inverse of b2a_hex().
        hexstr must contain an even number of hexadecimal digits (which can be upper or lower case), otherwise a TypeError is raised.

        :param data: hexadecimal string
        :return: binary
        """
        return safeBinaryFromHex(data)

    @classmethod
    def numberFromString(cls, string):
        """
        Get a number representation of a string

        :param String to be converted in a number
        :return: Number in hex from string
        """
        return int(cls.hexFromBinary(string), 16)

    @classmethod
    def stringFromNumber(cls, number, length):
        """
        Get a string representation of a number

        :param number to be converted in a string
        :param length max number of character for the string
        :return: hexadecimal string
        """

        fmtStr = "%0" + str(2 * length) + "x"
        return toString(cls.binaryFromHex((fmtStr % number).encode()))
