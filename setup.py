#!/usr/bin/env python
"""GreyNoise API client package."""
import os

from setuptools import find_packages, setup


def read(fname):
    """Read file and return its contents."""
    with open(os.path.join(os.path.dirname(__file__), fname)) as input_file:
        return input_file.read()


INSTALL_REQUIRES = [
    "Click>=8.0.0",
    "ansimarkup",
    "cachetools",
    "colorama",
    "click-default-group",
    "click-repl",
    "dict2xml",
    "ipaddress",
    "jinja2",
    "more-itertools",
    "requests",
    "six",
]

setup(
    name="greynoise",
    version="2.0.0",
    description="Abstraction to interact with GreyNoise API.",
    url="https://greynoise.io/",
    author="GreyNoise Intelligence",
    author_email="hello@greynoise.io",
    license="MIT",
    package_dir={"": "src"},
    packages=find_packages(where="src"),
    package_data={"greynoise.cli": ["templates/*.j2"]},
    install_requires=INSTALL_REQUIRES,
    long_description=read("README.rst") + "\n\n" + read("CHANGELOG.rst"),
    python_requires=">=3.0, !=3.0.*, !=3.1.*, !=3.2.*, !=3.3.*, !=3.4.*, !=3.5.*",
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Natural Language :: English",
        "Programming Language :: Python",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Topic :: Software Development :: Libraries",
    ],
    entry_points={"console_scripts": ["greynoise = greynoise.cli:main"]},
    zip_safe=False,
    keywords=["internet", "scanning", "threat intelligence", "security"],
    download_url="https://github.com/GreyNoise-Intelligence/pygreynoise",
)
