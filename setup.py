#!/usr/bin/env python
import os
from setuptools import setup, find_packages


def read(fname):
    return open(os.path.join(os.path.dirname(__file__), fname)).read()

setup(
    name='greynoise',
    version='0.1.0',
    description='Abstraction to interact with GreyNoise API.',
    url="",
    author="Brandon Dixon",
    author_email="brandon@9bplus.com",
    license="MIT",
    packages=find_packages(),
    install_requires=['requests'],
    long_description=read('README.rst'),
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Natural Language :: English',
        'Programming Language :: Python',
        'Topic :: Software Development :: Libraries'
    ],
    entry_points={
        'console_scripts': [
            'greynoise = greynoise.cli.manage:main'
        ]
    },
    zip_safe=False,
    keywords=['internet', 'scanning', 'threat intelligence', 'security'],
    download_url=''
)
