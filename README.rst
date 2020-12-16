================
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

Documentation
=============
Documentation is available here: `Documentation`_

.. _Documentation: https://developer.greynoise.io/docs/libraries-sample-code

Quick Start
===========
**Install the library**:

``pip install greynoise`` or ``python setup.py install``

**Save your configuration**:

``greynoise setup --api-key <your-API-key>``

Versioning
==========
This python package follows semantic versioning. According to this:

* We will NEVER push a breaking change without a major version release.
* We will only add new features and/or bug fixes with minor version releases.
* We will only do bug fixes for patch version release.

As such, we recommend you pin the dependency on this SDK to only allow minor version changes at most:

::
    
    # allow patch version increments
    greynoise~=1.4.0
    
    # allow minor verison increments
    greynoise~=1.4


Usage
=====
::

    Usage: greynoise [OPTIONS] COMMAND [ARGS]...

      GreyNoise CLI.

    Options:
      -h, --help  Show this message and exit.

    Commands:
      query*       Run a GNQL (GreyNoise Query Language) query.
      account      View information about your GreyNoise account.
      alerts       List, create, delete, and manage your GreyNoise alerts.
      analyze      Analyze the IP addresses in a log file, stdin, etc.
      feedback     Send feedback directly to the GreyNoise team.
      filter       "Filter the noise from a log file, stdin, etc.
      help         Show this message and exit.
      interesting  Report an IP as "interesting".
      ip           Query GreyNoise for all information on a given IP.
      pcap         Get PCAP for a given IP address.
      quick        Quickly check whether or not one or many IPs are "noise".
      repl         Start an interactive shell.
      setup        Configure API key.
      signature    Submit an IDS signature to GreyNoise to be deployed to all...
      stats        Get aggregate stats from a given GNQL query.
      version      Get version and OS information for your GreyNoise
                   commandline...

