from os import path
from setuptools import setup, find_packages

with open(path.join(path.dirname(__file__), "README.md")) as readme:
    README = readme.read()

setup(
    name="starkbank-ecdsa",
    packages=find_packages(),
    include_package_data=True,
    description="A lightweight and fast pure python ECDSA library",
    long_description=README,
    license="MIT License",
    url="https://github.com/starkbank/ecdsa-python.git",
    author="Stark Bank",
    author_email="rafael@starkbank.com",
    keywords=["ecdsa", "elliptic curve", "elliptic", "curve", "stark bank", "starkbank", "cryptograph"],
    version = "0.1"
)

# python setup.py sdist upload -r pypi