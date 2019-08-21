#!/usr/bin/env python
"""GreyNoise API client package."""
import os

from setuptools import find_packages, setup


def read(fname):
    """Read file and return its contents."""
    with open(os.path.join(os.path.dirname(__file__), fname)) as input_file:
        return input_file.read()


INSTALL_REQUIRES = ["click", "click-default-group", "dicttoxml", "requests"]

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
    package_data={"greynoise.cli": ["templates/*.j2"]},
    install_requires=INSTALL_REQUIRES,
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
