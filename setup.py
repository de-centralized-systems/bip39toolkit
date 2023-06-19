import pathlib
import setuptools

import bip39toolkit


PROJ_DIR = pathlib.Path(__file__).absolute().parent


def read(filename: str) -> str:
    """Return the contexts of the given text file located within the project root directory."""
    with open(PROJ_DIR / filename) as f:
        return f.read().strip()


setuptools.setup(
    name=bip39toolkit.__name__,
    version=bip39toolkit.VERSION,
    description=(
        "The BIP39 toolkit is a self-contained command line application, "
        "which provides an interface to generate, secret share and recover BIP39 mnemonic phrases."
    ),
    url="https://github.com/de-centralized-systems/python-bip39toolkit/",
    long_description=read("README.md"),
    long_description_content_type="text/markdown",
    author="Philipp Schindler and Aljosha Judmayer",
    extras_require={"dev": ["pytest", "pytest-cov"]},
    install_requires=[],
    py_modules=["bip39toolkit"],
    scripts=["bip39toolkit.py"],
    classifiers=[
        "Development Status :: 4 - Beta",  # 5 - Production/Stable;
        "Environment :: Console",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3.9",
        "Topic :: Security",
        "Topic :: Utilities",
    ],
    project_urls={
        "Source": "https://github.com/de-centralized-systems/python-bip39toolkit/",
        "Bug Tracker": "https://github.com/de-centralized-systems/python-bip39toolkit/issues",
    },
    python_requires=">=3.9.0",
)
