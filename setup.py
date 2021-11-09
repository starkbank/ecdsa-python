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
    long_description_content_type="text/markdown",
    license="MIT License",
    url="https://github.com/starkbank/ecdsa-python.git",
    author="Stark Bank",
    author_email="developers@starkbank.com",
    keywords=["ecdsa", "elliptic curve", "elliptic", "curve", "stark bank", "starkbank", "cryptograph", "secp256k1", "prime256v1"],
    version="2.0.2"
)


### Create a source distribution:

#Run ```python setup.py sdist``` inside the project directory.

### Install twine:

#```pip install twine```

### Upload package to pypi:

#```twine upload dist/*```

