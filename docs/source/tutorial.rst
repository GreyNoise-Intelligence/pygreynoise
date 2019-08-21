Tutorial
########

API client
==========

Create client object
--------------------

To interact with the API, a client object needs to be created::

   >>> from greynoise import GreyNoise
   >>> api_client = GreyNoise(<api_key>)

where *api_key* is the key you have been given to use the API.

.. note::

   The *api_key* is an optional parameter and might not be required if it's been stored
   in the configuration file using **greynose setup --api-key <api_key>**.


Check specific IPs
------------------

Once the client object has been created, it's possible to check if a given IP is
considered internet noise or has been observed scanning or attacking devices across the
Internet as follows::

   >>> api_client.get_noise_status("0.0.0.0")
   {'ip': '0.0.0.0', 'noise': True, 'code': '0x02', 'code_message': 'IP has been observed scanning the GreyNoise sensor network, but has not completed a full connection, meaning this can be spoofed'}

When there's a list of IP addresses to verify, they can be checked all at once like
this::

   >>> client.get_noise_status_bulk(['0.0.0.0', '0.0.0.1'])
   [{'ip': '0.0.0.0', 'noise': True, 'code': '0x02', 'code_message': 'IP has been observed scanning the GreyNoise sensor network, but has not completed a full connection, meaning this can be spoofed'}, {'ip': '0.0.0.1', 'noise': False, 'code': '0x00', 'code_message': 'IP has never been observed scanning the Internet'}]

Detailed context information for any given IP address is also available::

   >>> api_client.get_context('0.0.0.0')
   {'ip': '0.0.0.0', 'seen': True, 'classification': 'unknown', 'first_seen': '2019-01-29', 'last_seen': '2019-08-09', 'actor': 'unknown', 'tags': ['ZMap Client'], 'metadata': {'country': '', 'country_code': '', 'city': '', 'organization': '', 'asn': '', 'tor': False, 'os': 'unknown', 'category': ''}, 'raw_data': {'scan': [{'port': 67, 'protocol': 'UDP'}], 'web': {'paths': [], 'useragents': []}, 'ja3': []}}


GNQL
----

Run a query
~~~~~~~~~~~

A GNQL (GreyNoise Query Language) query can be executed to dig deeper into the GreyNoise
dataset. For example, to get context information related to the IP address 0.0.0.0 whose
activity has been classified as malicious and tagged as an HTTP-Alt scanner::

   >>> api_client.run_query('0.0.0.0 classification:malicious tags:HTTP Alt Scanner')
   {'complete': True, 'count': 1, 'data': [{'ip': '115.22.104.83', 'seen': True, 'classification': 'malicious', 'first_seen': '2019-02-11', 'last_seen': '2019-04-25', 'actor': 'unknown', 'tags': ['HTTP Alt Scanner', 'Mirai', 'Residential', 'Telnet Bruteforcer', 'Telnet Scanner', 'Telnet Worm'], 'metadata': {'country': 'South Korea', 'country_code': 'KR', 'city': 'Ulsan', 'organization': '0.0.0.0 - 127.255.255.255', 'rdns': '', 'asn': 'AS4766', 'tor': False, 'os': 'Linux 2.2.x-3.x (Embedded)', 'category': 'business'}, 'raw_data': {'scan': [{'port': 23, 'protocol': 'TCP'}, {'port': 81, 'protocol': 'TCP'}], 'web': {}, 'ja3': []}}], 'message': 'ok', 'query': '0.0.0.0 classification:malicious tags:HTTP Alt Scanner'}


Get statistics
~~~~~~~~~~~~~~

It's also possible to get statistics related to a GNQL query to better understand how
results are distributed in terms of different information such as organization, country,
operating system, etc.:

   >>> api_client.run_stats_query('0.0.0.0 classification:malicious tags:HTTP Alt Scanner')
   {'query': '0.0.0.0 classification:malicious tags:HTTP Alt Scanner', 'count': 1, 'stats': {'classifications': [{'classification': 'malicious', 'count': 1}], 'organizations': [{'organization': '0.0.0.0 - 127.255.255.255', 'count': 1}], 'actors': None, 'countries': [{'country': 'South Korea', 'count': 1}], 'tags': [{'tag': 'HTTP Alt Scanner', 'count': 1}, {'tag': 'Mirai', 'count': 1}, {'tag': 'Residential', 'count': 1}, {'tag': 'Telnet Bruteforcer', 'count': 1}, {'tag': 'Telnet Scanner', 'count': 1}, {'tag': 'Telnet Worm', 'count': 1}], 'operating_systems': [{'operating_system': 'Linux 2.2.x-3.x (Embedded)', 'count': 1}], 'categories': [{'category': 'business', 'count': 1}], 'asns': [{'asn': 'AS4766', 'count': 1}]}}


Command line interface
======================

The same operations available through the API client are also available through
the command line using the *greynoise* tool. To get a list of all the available
subcommands, use the *--help* option::

   $ greynoise --help
   Usage: greynoise [OPTIONS] COMMAND [ARGS]...

   Entry point for the greynoise CLI.

   :param argv: Command line arguments :type: list

   Options:
   -k, --api-key TEXT           Key to include in API requests
   -f, --format [json|txt|xml]  Output format
   -v, --verbose                Verbose output
   --help                       Show this message and exit.

   Commands:
   gnql*   GNQL queries.
   actors  Run actors query.
   ip      IP lookup.
   setup   Configure API key.


Setup
-----

To configure *greynoise* to use a given API key::

   $ greynoise setup --api-key "<api_key>"
   Configuration saved to '/home/javi/.config/greynoise/config'

.. note::

   This is the default configuration method. Alternatively, the API key can be passed to every command using the *-k/--api-key* option
   or through the *GREYNOISE_API_KEY* environment variable.


Check specific IPs
------------------

Once the command line tool has been created, it's possible to check if a given IP is
considered internet noise or has been observed scanning or attacking devices across the
Internet as follows::

   $ greynoise ip quick-check 0.0.0.0
   0.0.0.0 is classified as NOISE.

When there's a list of IP addresses to verify, they can be checked all at once like
this::

   $ greynoise ip multi-quick-check 0.0.0.0 0.0.0.1
   0.0.0.0 is classified as NOISE.
   0.0.0.1 is classified as NOT NOISE.

Detailed context information for any given IP address is also available::

   $ greynoise ip context 0.0.0.0
            OVERVIEW:
   ----------------------------
   Actor: unknown
   Classification: unknown
   First seen: 2019-01-29
   IP: 0.0.0.0
   Last seen: 2019-08-21
   Tags:
   - ZMap Client

            METADATA:
   ----------------------------
   ASN:
   Category:
   Location:
   Organization:
   OS: unknown
   rDNS:
   Tor: False

            RAW DATA:
   ----------------------------
   [Scan]
   - Port/Proto: 67/UDP

GNQL
----

Run a query
~~~~~~~~~~~

A GNQL (GreyNoise Query Language) query can be executed to dig deeper into the GreyNoise
dataset. For example, to get context information related to the IP address 0.0.0.0 whose
activity has been classified as malicious and tagged as an HTTP-Alt scanner::

   $ greynoise gnql query "0.0.0.0 classification:malicious tags:HTTP Alt Scanner"
   ┌───────────────────────────┐
   │       Result 1 of 1       │
   └───────────────────────────┘

            OVERVIEW:
   ----------------------------
   Actor: unknown
   Classification: malicious
   First seen: 2019-02-11
   IP: 115.22.104.83
   Last seen: 2019-04-25
   Tags:
   - HTTP Alt Scanner
   - Mirai
   - Residential
   - Telnet Bruteforcer
   - Telnet Scanner
   - Telnet Worm

            METADATA:
   ----------------------------
   ASN: AS4766
   Category: business
   Location: Ulsan, South Korea (KR)
   Organization: 0.0.0.0 - 127.255.255.255
   OS: Linux 2.2.x-3.x (Embedded)
   rDNS:
   Tor: False

            RAW DATA:
   ----------------------------
   [Scan]
   - Port/Proto: 23/TCP
   - Port/Proto: 81/TCP

.. note::

   This is the default command, that is, you can save some typing by just
   writing **greynoise <query>** instead of **greynose gnql query <query>**.


Get statistics
~~~~~~~~~~~~~~

It's also possible to get statistics related to a GNQL query to better understand how
results are distributed in terms of different information such as organization, country,
operating system, etc.::

   $ greynoise gnql stats "0.0.0.0 classification:malicious tags:HTTP Alt Scanner"
   ASNs:
   - AS4766: 1

   Categories:
   - business: 1

   Classifications:
   - malicious: 1

   Countries:
   - South Korea: 1

   Operating systems:
   - Linux 2.2.x-3.x (Embedded): 1

   Organizations:
   - 0.0.0.0 - 127.255.255.255: 1

   Tags:
   - HTTP Alt Scanner: 1
   - Mirai: 1
   - Residential: 1
   - Telnet Bruteforcer: 1
   - Telnet Scanner: 1
   - Telnet Worm: 1

