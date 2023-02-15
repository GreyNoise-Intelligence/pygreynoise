=========
Changelog
=========

Version `2.0.0`_
================
**Date**: February 15, 2023

* BREAKING CHANGE:

  * Removed support for python 3.5

* API client:

  * Added `similar` command to support IP Similarity lookups
  * Added `timeline` command to support IP Time Series Single Attribute lookups
  * Added `timelinehourly` command to support IP Time Series Hourly Summary lookups
  * Added `timelinedaily` command to support IP Time Series Daily Summary lookups
  * Added `exclude_raw` parameter to query command to reduce issues with default behavior in integrations

* CLI:

  * Added `similar` command to support IP Similarity lookups
  * Added `timeline` command to support IP Time Series Single Attribute lookups
  * Added `timelinehourly` command to support IP Time Series Hourly Summary lookups
  * Added `timelinedaily` command to support IP Time Series Hourly Summary lookups

* Dependencies:

  * Updated dict2xml to version 1.7.2
  * Updated colorama to version 0.4.6
  * Updated cachetools to version 5.3.0

Version `1.3.0`_
================
**Date**: September 07, 2022

* API client:

  * Rework logging to remove structlog predefined logging to follow best practices
  * Update the `quick` command to use a POST API request instead of a GET API request
  * Fix bug with `ip_multi` preventing lists of more than 1000 entries from returning correct data
  * Fix bug with `ip_multi` when cache is disabled not returning correct values
  * Fix bug with `ip_multi` where `include_invalid` parameter was not working

* CLI:

  * None

* Dependencies:

  * Updated Click to 8.1.3
  * Updated colorama to 0.4.5
  * Updated jinja2 to 3.1.2
  * Updated more-itertools to 8.14.0
  * Update requests to 2.28.1
  * Removed structlog

Version `1.2.1`_
================
**Date**: June 03, 2022

* API client:

  * None

* CLI:

  * Add missing HASSH values to output for IP and QUERY commands
  * Remove unused PCAP command

* Dependencies:

  * Update jinja to 3.1.0
  * Update dict2xml to 1.7.1
  * Update Click to 8.1.2
  * Update more-itertools to 8.13.0
  * Update cachetools to 5.2.0

Version `1.2.0`_
================
**Date**: September 03, 2021

* API client:

  * Add ip_multi command to support bulk IP Context lookups
  * Fix issue with "include_invalid" option on quick command failing with "riot" key missing

* CLI:

  * Add ip-multi command to support bulk IP Context lookups
  * Add support for comma separated IP lists for ip-multi and quick commands
  * Add size and scroll arguments for query and stats command
  * Update quick command to not error completely when non-routable IP is passed as an input in a list

* Dependencies:

  * Added colorama dependency
  * Update Click to 8.0.3
  * Updated cachetools to 5.0.0
  * Updated jinja to 3.0.3
  * Updated more-itertools to 8.12.0
  * Updated requests to 2.27.1
  * Updated structlog to 21.5.0

Version `1.1.0`_
================
**Date**: June 23, 2021

* API client:

  * Update filter command to use new quick endpoint with noise/riot updates
  * Update analyze command to use new quick endpoint with noise/riot updates

* CLI:

  * Update quick command to handle quick endpoint noise/riot updates
  * Add support for RIOT trust_level output

* Dependencies:

  * Updated Click to 8.0.1

Version `1.0.0`_
================
**Date**: June 02, 2021

*** Removed Support for Python2 - BREAKING CHANGE ***

* API client:

  * Fixed error handling for both `error` and `message` responses
  * Implemented ipaddress package for IP validation to prevent non-routable IP addresses from being
    sent for query to the API

* CLI:

  * Updated warning messages to help identify invalid vs non-routable IPs

* Dependencies:

  * Updated cachetools to 4.2.2
  * Updated six to 1.16.0
  * Updated jinja2 to 3.0.1 for py36 and py37
  * Updated click-repl to 0.2.0
  * Updated more-itertools to 8.8.0

Version `0.9.1`_
================
**Date**: May 05, 2021

* CLI:

  * #465: Fixed error handling on expired API key

* Dependencies:

  * Updated cachetools to 4.2.2

Version `0.9.0`_
================
**Date**: April 21, 2021

* API client:

  * Removed rouge debug statement from analysis command

* CLI:

  * Fixed query command to display text output for queries with more than 10k results
    * Query now limits results to 10 on the text output

Version `0.8.0`_
================
**Date**: March 26, 2021

* API client:

  * Added support for Community API
  * Added information about "integration_name" parameter to docs
  * **BREAKING CHANGE** Updated test_connection() to use /ping endpoint and return API response
    message and exception instead of string values

* CLI:

  * Added support for Community API
  * Updated Analyze command to include RIOT
  * Changed default behavior to no longer use `query`.  Invalid commands return error now

* Dependencies:

  * Updated cachetools to 4.2.1
  * Updated jinja2 to 2.11.3
  * Updated more-itertools to 8.7.0
  * Update structlog to 21.1.0


Version `0.7.0`_
================
**Date**: January 07, 2021

* API client:

  * Add "include_invalid" option to QUICK lookup to return invalid IPs as part of the JSON response
  * Added support for new /riot endpoint
  * Updated logic in quick to better handle non-list format input ('ip_1,ip_2')instead of
    ['ip_1','ip_2']
  * Added ability to configure CACHE TTL and CACHE MAX SIZE instead of only using hardcoded defaults

* CLI:

  * Added support for new riot command
  * Updated json_formatter for query commands to return data only as New Line Delimited JSON

* Dependencies:

  * Updated sphinx to 3.4.0
  * Updated structlog to 20.2.0 for python 3.6 and 3.7

Version `0.6.0`_
================
**Date**: December 21, 2020

* API client:

  * Added ``test_connection`` method to allow for integrations to validate connection and API key

* CLI:

  * Added spoofable and CVE outputs where possible

* Both API client and CLI:

  * Fix IP_Validation method bug which was preventing valid IPs from being submitted

Version `0.5.0`_
================
**Date**: December 16, 2020

* API client:

  * add ``metadata`` method.
  * replace `dicttoxml` with `dict2xml` for license-compatibility.

* Both API client and CLI:

  * Update dependencies to the latest version
  * Add support for PROXY usage
  * Update the IP validator to ensure better validation

Version `0.4.1`_
================
**Date**: January 3, 2020

* API client:

  * add ``spoofable`` field.

Version `0.4.0`_
================
**Date**: November 18, 2019

* API client:

  * add ``interesting`` method.
  * add ``filter`` method.
  * add ``analyze`` method.
  * add ``scroll`` and ``size`` parameters to ``query`` method.
  * add ``api_server`` and ``integration_name`` parameters to ``__init__`` method.

* CLI:

  * add ``interesting`` subcommand.
  * add ``filter`` subcommand.
  * add ``analyze`` subcommand.
  * add ``api_server`` option to setup subcommand.

* Both API client and CLI:
  * use structlog logging library.

Version `0.3.0`_
================
**Date**: September 06, 2019

* API client:

  * rename API client methods to match CLI command names.
  * use LRU cache for IP context and quick check calls.

* CLI:

  * add help, repl and version subcommands.
  * global options moved to those subcommands where they apply.
  * make request timeout configurable.


Version `0.2.2`_
================
**Date**: August 28, 2019

* CLI:

  * fix ``setup`` subcommand when configuration directory doesn't exist.


Version `0.2.1`_
================
**Date**: August 28, 2019

* API client

  * Version sent in ``User-Agent`` header.
  * Raise ``RateLimitError`` on 429 response.

* CLI

  * Colored output.
  * Add ``-i / --input`` option.


Version `0.2.0`_
================
**Date**: August 21, 2019

* Complete codebase refactoring.


.. _`0.2.0`: https://github.com/GreyNoise-Intelligence/pygreynoise/compare/df4af7c392c50a5a0ebb5d761d7c67de6208c2c1...v0.2.0
.. _`0.2.1`: https://github.com/GreyNoise-Intelligence/pygreynoise/compare/v0.2.0...v0.2.1
.. _`0.2.2`: https://github.com/GreyNoise-Intelligence/pygreynoise/compare/v0.2.1...v0.2.2
.. _`0.3.0`: https://github.com/GreyNoise-Intelligence/pygreynoise/compare/v0.2.2...v0.3.0
.. _`0.4.0`: https://github.com/GreyNoise-Intelligence/pygreynoise/compare/v0.3.0...0.4.0
.. _`0.4.1`: https://github.com/GreyNoise-Intelligence/pygreynoise/compare/v0.4.0...0.4.1
.. _`0.5.0`: https://github.com/GreyNoise-Intelligence/pygreynoise/compare/v0.4.1...0.5.0
.. _`0.6.0`: https://github.com/GreyNoise-Intelligence/pygreynoise/compare/v0.5.0...0.6.0
.. _`0.7.0`: https://github.com/GreyNoise-Intelligence/pygreynoise/compare/v0.6.0...0.7.0
.. _`0.8.0`: https://github.com/GreyNoise-Intelligence/pygreynoise/compare/v0.7.0...0.8.0
.. _`0.9.0`: https://github.com/GreyNoise-Intelligence/pygreynoise/compare/v0.8.0...0.9.0
.. _`0.9.1`: https://github.com/GreyNoise-Intelligence/pygreynoise/compare/v0.9.0...0.9.1
.. _`1.0.0`: https://github.com/GreyNoise-Intelligence/pygreynoise/compare/v0.9.1...1.0.0
.. _`1.1.0`: https://github.com/GreyNoise-Intelligence/pygreynoise/compare/v1.0.0...1.1.0
.. _`1.2.0`: https://github.com/GreyNoise-Intelligence/pygreynoise/compare/v1.1.0...1.2.0
.. _`1.2.1`: https://github.com/GreyNoise-Intelligence/pygreynoise/compare/v1.2.0...1.2.1
.. _`1.3.0`: https://github.com/GreyNoise-Intelligence/pygreynoise/compare/v1.2.1...1.3.0
.. _`2.0.0`: https://github.com/GreyNoise-Intelligence/pygreynoise/compare/v1.3.0...HEAD
