#!/usr/bin/env python
"""GreyNoise API client package."""
import os
from setuptools import setup, find_packages


def read(fname):
    """Read file and return its contents."""
    with open(os.path.join(os.path.dirname(__file__), fname)) as input_file:
        return input_file.read()


INSTALL_REQUIRES = ["dicttoxml", "requests"]

TEST_REQUIRES = ["flake8", "mock", "pylint", "pytest", "pytest-cov"]

setup(
    name="greynoise",
    version="0.1.5",
    description="Abstraction to interact with GreyNoise API.",
    url="https://greynoise.io/",
    author="GreyNoise Intelligence",
    author_email="hello@greynoise.io",
    license="MIT",
    package_dir={"": "src"},
    packages=find_packages(where="src"),
    install_requires=INSTALL_REQUIRES,
    test_requires=TEST_REQUIRES,
    long_description=read("README.rst"),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Natural Language :: English",
        "Programming Language :: Python",
        "Topic :: Software Development :: Libraries",
    ],
    entry_points={"console_scripts": ["greynoise = greynoise.cli:main"]},
    zip_safe=False,
    keywords=["internet", "scanning", "threat intelligence", "security"],
    download_url="https://github.com/GreyNoise-Intelligence/pygreynoise",
)
