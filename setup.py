from os import path
from setuptools import setup, find_packages


with open(path.join(path.dirname(__file__), "README.md")) as readme:
    README = readme.read()


setup(
    name="starkbank-ecdsa",
    packages=find_packages(exclude=["tests"]),
    include_package_data=True,
    description="A lightweight and fast pure python ECDSA library",
    long_description=README,
    long_description_content_type="text/markdown",
    license="MIT License",
    url="https://github.com/starkbank/ecdsa-python.git",
    author="Stark Bank",
    author_email="developers@starkbank.com",
    keywords=["ecdsa", "elliptic curve", "elliptic", "curve", "stark bank", "starkbank", "cryptograph", "secp256k1", "prime256v1"],
    python_requires=">=2.7, !=3.0.*, !=3.1.*, !=3.2.*, !=3.3.*",
    version="2.2.0"
)


### Create a source distribution and a universal wheel:

#Run ```python setup.py sdist bdist_wheel``` inside the project directory.

### Install twine and wheel:

#```pip install twine wheel```

### Upload package to pypi:

#```twine upload dist/*```

