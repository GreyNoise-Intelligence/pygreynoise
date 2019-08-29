Python GreyNoise
================

.. image:: https://circleci.com/gh/GreyNoise-Intelligence/pygreynoise.svg?style=shield
    :target: https://circleci.com/gh/GreyNoise-Intelligence/pygreynoise

.. image:: https://sonarcloud.io/api/project_badges/measure?project=GreyNoise-Intelligence_pygreynoise&metric=coverage
    :target: https://sonarcloud.io/dashboard?id=GreyNoise-Intelligence_pygreynoise

.. image:: https://readthedocs.org/projects/greynoise/badge/?version=latest
    :target: http://greynoise.readthedocs.io/en/latest/?badge=latest

.. image:: https://badge.fury.io/py/greynoise.svg
    :target: https://badge.fury.io/py/greynoise


.. image:: https://pyup.io/repos/github/GreyNoise-Intelligence/pygreynoise/shield.svg
    :target: https://pyup.io/repos/github/GreyNoise-Intelligence/pygreynoise/
    :alt: Updates

.. image:: https://img.shields.io/badge/License-MIT-yellow.svg
    :target: https://opensource.org/licenses/MIT

.. image:: https://quay.io/repository/greynoiseintel/pygreynoise/status
    :target: https://quay.io/repository/greynoiseintel/pygreynoise

This is an abstract python library built on top of the `GreyNoise`_ service. It is preferred that users use this library when implementing integrations or plan to use GreyNoise within their code. The library includes a small client to interact with the API.

.. _GreyNoise: https://greynoise.io/

Quick Start
-----------
**Install the library**:

``pip install greynoise`` or ``python setup.py install``

**Save your configuration**:

``greynoise setup --api-key <your-API-key>``

Changelog
---------
03-27-19
~~~~~~~~
* Merge CLI and pip module

11-08-18
~~~~~~~~
* Change: Updated codes to reflect latest documents
* Bugfix: Handle cases when code is unknown

05-25-18
~~~~~~~~
* Complete overhaul of the library
