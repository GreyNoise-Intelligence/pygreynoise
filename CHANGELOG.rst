=========
Changelog
=========

Version `0.9.0`_
================
**Date**: April 21, 2021

* API client:

  * Removed rouge debug statement from analysis command

* CLI

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
