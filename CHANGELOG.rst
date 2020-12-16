=========
Changelog
=========

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

* CLI: fix ``setup`` subcommand when configuration directory doesn't exist.


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
