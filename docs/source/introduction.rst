============
Introduction
============

**greynoise** is a python library to work with the `GreyNoise API`_.

In particular, it will allow you to:

- check if a set of IP addresses are "Internet background noise", or have been
  observed scanning or attacking devices across the Internet.

- get context information associated with an API address such as time ranges,
  IP metadata (network owner, ASN, reverse DNS pointer, country), associated
  actors, activity tags, and raw port scan and web request information.

- get a list of noise IP address found in a given date.

- check if an IP address belongs to a common business service

.. _GreyNoise API: https://docs.greynoise.io/reference
