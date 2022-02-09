========
Tutorial
========

API client
==========

Create client object
--------------------

To interact with the API, a client object needs to be created::

   >>> from greynoise import GreyNoise
   >>> api_client = GreyNoise(api_key=<api_key>, timeout=<timeout_in_seconds>, proxy=<proxy_url>,
       use_cache=True, cache_max_size=1000, cache_ttl=3600, integration_name=<name_of_integration>)

where:

- *api_key* is the key you have been given to use the API.
- *timeout_in_seconds* is the timeout for each request sent to the API.
- *proxy* is the url (ex `http://myproxy.corp.io:1234`) for requests to be routed through.
- *use_cache* is used to disable (enabled by default) use of local cache for lookups.
- *cache_max_size* is used to define the max size of the cache, if enabled.
- *cache_ttl* is used to define the TTL of the data in the cache, if enabled.
- *integration_name* is used to define the name of an integration the SDK is built into, if needed.

.. note::

   All parameters are optional and might not be required if a
   configuration file has been created using the ``greynoise setup`` CLI command.


Check specific IPs
------------------

Once the client object has been created, it's possible to check if a given IP is
considered internet noise or has been observed scanning or attacking devices across the
Internet as follows::

    >>> api_client.quick('8.8.8.8')
    {
      "ip": "8.8.8.8",
      "noise": false,
      "code": "0x05",
      "code_message": "This IP is commonly spoofed in Internet-scan activity"
    }

When there's a list of IP addresses to verify, they can be checked all at once like
this::

    >>> api_client.quick(['8.8.8.8', '58.220.219.247'])
    [
      {
        "ip": "8.8.8.8",
        "noise": false,
        "code": "0x05",
        "code_message": "This IP is commonly spoofed in Internet-scan activity"
      },
      {
        "ip": "58.220.219.247",
        "noise": true,
        "code": "0x01",
        "code_message": "The IP has been observed by the GreyNoise sensor network"
      }
    ]

When there's a list of IP addresses to verify, and invalid IPs provide should be included in the
output they can be checked all at once like this::

    >>> api_client.quick(['8.8.8.8', '58.220.219.247', '110.153.82.818'],include_invalid=True)
    [
      {
        "ip": "8.8.8.8",
        "noise": false,
        "code": "0x05",
        "code_message": "This IP is commonly spoofed in Internet-scan activity"
      },
      {
        "ip": "58.220.219.247",
        "noise": true,
        "code": "0x01",
        "code_message": "The IP has been observed by the GreyNoise sensor network"
      },
      {
      "ip": "110.153.82.818",
      "noise": False,
      "code": "404",
      "code_message": "IP is Invalid"}
    ]

Detailed context information for any given IP address is also available::

    >>> api_client.ip('58.220.219.247')
    {
      "ip": "58.220.219.247",
      "seen": true,
      "classification": "malicious",
      "first_seen": "2019-04-04",
      "last_seen": "2019-08-21",
      "actor": "unknown",
      "tags": [
        "MSSQL Bruteforcer",
        "MSSQL Scanner",
        "RDP Scanner"
      ],
      "metadata": {
        "country": "China",
        "country_code": "CN",
        "city": "Kunshan",
        "organization": "CHINANET jiangsu province network",
        "asn": "AS4134",
        "tor": false,
        "os": "Windows 7/8",
        "category": "isp"
      },
      "raw_data": {
        "scan": [
          {
            "port": 1433,
            "protocol": "TCP"
          },
          {
            "port": 3389,
            "protocol": "TCP"
          },
          {
            "port": 65529,
            "protocol": "TCP"
          }
        ],
        "web": {
          "paths": [],
          "useragents": []
        },
        "ja3": []
      }
    }

When there's a list of IP addresses to get full context from, they can be checked all at once like
this (this method also supports the include_invalid flag::

    >>> api_client.ip_multi(['8.8.8.8', '58.220.219.247'])
      [
    {
      'ip': '8.8.8.8',
      'first_seen': '',
      'last_seen': '',
      'seen': False,
      'tags': None,
      'actor': '',
      'spoofable': False,
      'classification': '',
      'cve': None,
      'bot': False,
      'vpn': False,
      'vpn_service': '',
      'metadata': {
        'asn': '',
        'city': '',
        'country': '',
        'country_code': '',
        'organization': '',
        'category': '',
        'tor': False,
        'rdns': '',
        'os': ''
      },
      'raw_data': {
        'scan': [],
        'web': {},
        'ja3': [],
        'hassh': []
      }
    },
    {
      'ip': '58.220.219.247',
      'first_seen': '',
      'last_seen': '',
      'seen': False,
      'tags': None,
      'actor': '',
      'spoofable': False,
      'classification': '',
      'cve': None,
      'bot': False,
      'vpn': False,
      'vpn_service': '',
      'metadata': {
        'asn': '',
        'city': '',
        'country': '',
        'country_code': '',
        'organization': '',
        'category': '',
        'tor': False,
        'rdns': '',
        'os': ''
      },
      'raw_data': {
        'scan': [],
        'web': {},
        'ja3': [],
        'hassh': []
      }
    }
  ]

Any IP can also be checked to see if it exists within the RIOT dataset::

    >>> api_client.riot('8.8.8.8')
    {
      'ip': '8.8.8.8',
      'riot': True,
      'category': 'public_dns',
      'name': 'Google Public DNS',
      'description': "Google's global domain name system (DNS) resolution service.",
      'explanation': "Public DNS services are used as alternatives to ISP's name servers. You may see devices on your network communicating with Google Public DNS over port 53/TCP or 53/UDP to resolve DNS lookups.",
      'last_updated': '2022-02-08T18:58:27Z',
      'logo_url': 'https://upload.wikimedia.org/wikipedia/commons/2/2f/Google_2015_logo.svg',
      'reference': 'https://developers.google.com/speed/public-dns/docs/isp#alternative',
      'trust_level': '1'
    }

.. note::

    The ``ip`` and ``quick`` methods use an LRU cache with a timeout of one hour to
    return faster responses in case the same addresses are queried multiple times. It
    can be disabled to get live responses from the API by passing ``use_cache=False``
    when the ``GreyNoise`` class is instantiated.


GNQL
----

Run a query
~~~~~~~~~~~

A GNQL (GreyNoise Query Language) query can be executed to dig deeper into the GreyNoise
dataset. For example, to get context information related to activity has been classified
as malicious and tagged as a Bluekeep Exploit::

    >>> api_client.query('classification:malicious tags:"Bluekeep Exploit"')
    {
      "complete": true,
      "count": 2,
      "data": [
        {
          "ip": "144.217.253.168",
          "seen": true,
          "classification": "malicious",
          "first_seen": "2019-06-04",
          "last_seen": "2019-08-21",
          "actor": "unknown",
          "tags": [
            "RDP Scanner",
            "Bluekeep Exploit"
          ],
          "metadata": {
            "country": "Canada",
            "country_code": "CA",
            "city": "Montréal",
            "organization": "OVH SAS",
            "rdns": "ns541387.ip-144-217-253.net",
            "asn": "AS16276",
            "tor": false,
            "os": "Linux 3.11+",
            "category": "hosting"
          },
          "raw_data": {
            "scan": [
              {
                "port": 3389,
                "protocol": "TCP"
              }
            ],
            "web": {},
            "ja3": []
          }
        },
        {
          "ip": "91.213.112.119",
          "seen": true,
          "classification": "malicious",
          "first_seen": "2019-04-18",
          "last_seen": "2019-06-03",
          "actor": "unknown",
          "tags": [
            "Bluekeep Exploit",
            "RDP Scanner",
            "TLS/SSL Crawler",
            "Tor",
            "VNC Scanner",
            "Web Scanner",
            "Windows RDP Cookie Hijacker CVE-2014-6318"
          ],
          "metadata": {
            "country": "Netherlands",
            "country_code": "NL",
            "city": "",
            "organization": "Onsweb B.V.",
            "rdns": "no-reverse.onlinesystemen.nl",
            "asn": "AS42755",
            "tor": true,
            "os": "Linux 3.11+",
            "category": "business"
          },
          "raw_data": {
            "scan": [
              {
                "port": 443,
                "protocol": "TCP"
              },
              {
                "port": 3389,
                "protocol": "TCP"
              },
              {
                "port": 5900,
                "protocol": "TCP"
              }
            ],
            "web": {},
            "ja3": []
          }
        }
      ],
      "message": "ok",
      "query": "classification:malicious tags:'Bluekeep Exploit'"
    }


Get statistics
~~~~~~~~~~~~~~

It's also possible to get statistics related to a GNQL query to better understand how
results are distributed in terms of different information such as organization, country,
operating system, etc.::

    >>> api_client.stats('classification:malicious tags:"Bluekeep Exploit"')
    {
      "query": "classification:malicious tags:'Bluekeep Exploit'",
      "count": 24,
      "stats": {
        "classifications": [
          {
            "classification": "malicious",
            "count": 24
          }
        ],
        "organizations": [
          {
            "organization": "DigitalOcean, LLC",
            "count": 7
          },
          {
            "organization": "OVH SAS",
            "count": 6
          },
          {
            "organization": "China Unicom Shanghai network",
            "count": 3
          },
          {
            "organization": "Linode, LLC",
            "count": 3
          },
          {
            "organization": "Amarutu Technology Ltd",
            "count": 1
          },
          {
            "organization": "Amazon.com, Inc.",
            "count": 1
          },
          {
            "organization": "CHINANET-BACKBONE",
            "count": 1
          },
          {
            "organization": "INT-NETWORK",
            "count": 1
          },
          {
            "organization": "WideOpenWest Finance LLC",
            "count": 1
          }
        ],
        "actors": null,
        "countries": [
          {
            "country": "Canada",
            "count": 6
          },
          {
            "country": "United States",
            "count": 6
          },
          {
            "country": "China",
            "count": 4
          },
          {
            "country": "Germany",
            "count": 3
          },
          {
            "country": "Netherlands",
            "count": 3
          },
          {
            "country": "France",
            "count": 1
          },
          {
            "country": "United Kingdom",
            "count": 1
          }
        ],
        "tags": [
          {
            "tag": "Bluekeep Exploit",
            "count": 24
          },
          {
            "tag": "RDP Scanner",
            "count": 24
          },
          {
            "tag": "Telnet Scanner",
            "count": 1
          }
        ],
        "operating_systems": [
          {
            "operating_system": "Linux 3.11+",
            "count": 16
          },
          {
            "operating_system": "Windows 7/8",
            "count": 3
          },
          {
            "operating_system": "Mac OS X",
            "count": 2
          },
          {
            "operating_system": "Linux 2.2-3.x",
            "count": 1
          }
        ],
        "categories": [
          {
            "category": "hosting",
            "count": 17
          },
          {
            "category": "isp",
            "count": 6
          },
          {
            "category": "business",
            "count": 1
          }
        ],
        "asns": [
          {
            "asn": "AS14061",
            "count": 7
          },
          {
            "asn": "AS16276",
            "count": 6
          },
          {
            "asn": "AS17621",
            "count": 3
          },
          {
            "asn": "AS63949",
            "count": 3
          },
          {
            "asn": "AS12083",
            "count": 1
          },
          {
            "asn": "AS14618",
            "count": 1
          },
          {
            "asn": "AS202425",
            "count": 1
          },
          {
            "asn": "AS206264",
            "count": 1
          },
          {
            "asn": "AS4134",
            "count": 1
          }
        ]
      }
    }


Command line interface
======================

The same operations available through the API client are also available through
the command line using the *greynoise* tool. To get a list of all the available
subcommands, use the *--help* option::

    $ greynoise -h
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
    riot         Query GreyNoise IP to see if it is in the RIOT dataset.
    setup        Configure API key.
    signature    Submit an IDS signature to GreyNoise to be deployed to all...
    stats        Get aggregate stats from a given GNQL query.
    version      Get version and OS information for your GreyNoise
                commandline...

Setup
-----

To configure *greynoise* to use a given API key::

   $ greynoise setup --api-key "<api_key>"
   Configuration saved to '/home/username/.config/greynoise/config'

.. note::

   This is the default configuration method. Alternatively, the API key can be passed to every command using the *-k/--api-key* option
   or through the *GREYNOISE_API_KEY* environment variable.

if for some reason, requests are timing out, it's possible to set the request
timeout for the API client with the setup command as well::

   $ greynoise setup --api-key "<api_key>" --timeout <time_in_seconds>
   Configuration saved to '/home/username/.config/greynoise/config'

.. note::

   The API client request timeout can also be configured for a particular command using the *GREYNOISE_TIMEOUT* environment variable.

Check specific IPs
------------------

Once the command line tool has been created, it's possible to check if a given IP is
considered internet noise or has been observed scanning or attacking devices across the
Internet as follows::

   $ greynoise quick 58.220.219.247
   58.220.219.247 is classified as NOISE.

When there's a list of IP addresses to verify, they can be checked all at once like
this (a comma seperated list is also supported::

   $ greynoise quick 8.8.8.8 58.220.219.247
   8.8.8.8 is classified as NOT NOISE.
   58.220.219.247 is classified as NOISE.

Detailed context information for any given IP address is also available::

   $ greynoise ip 58.220.219.247
   ╔═══════════════════════════╗
   ║      Context 1 of 1       ║
   ╚═══════════════════════════╝
   IP address: 58.220.219.247

             OVERVIEW
   ----------------------------
   Actor: unknown
   Classification: malicious
   First seen: 2019-04-04
   IP: 58.220.219.247
   Last seen: 2019-09-06
   Tags:
   - MSSQL Bruteforcer
   - MSSQL Scanner
   - RDP Scanner

             METADATA
   ----------------------------
   ASN: AS4134
   Category: isp
   Location: Kunshan, China (CN)
   Organization: CHINANET jiangsu province network
   OS: Windows 7/8
   rDNS:
   Tor: False

             RAW DATA
   ----------------------------
   [Scan]
   - Port/Proto: 1433/TCP
   - Port/Proto: 3389/TCP
   - Port/Proto: 65529/TCP

When there's a list of IP addresses to verify, they can be checked all at once like
this (a comma seperated list is also supported::

   $ greynoise ip-multi 8.8.8.8 58.220.219.247
          OVERVIEW
    ----------------------------
    Actor: unknown
    Classification: malicious
    First seen: 2020-12-21
    IP: 42.230.170.174
    Last seen: 2022-02-08
    Tags:
    - Mirai

              METADATA
    ----------------------------
    ASN: AS4837
    Category: isp
    Location:
    Region: Heilongjiang
    Organization: CHINA UNICOM China169 Backbone
    OS: Linux 2.2-3.x
    rDNS: hn.kd.ny.adsl
    Spoofable: False
    Tor: False

              RAW DATA
    ----------------------------
    [Scan]
    - Port/Proto: 23/TCP
    - Port/Proto: 8080/TCP

    [Paths]
    - /setup.cgi

    8.8.8.8 is classified as NOT NOISE.



GNQL
----

Run a query
~~~~~~~~~~~

A GNQL (GreyNoise Query Language) query can be executed to dig deeper into the GreyNoise
dataset. For example, to get context information related to activity has been classified
as malicious and tagged as a Bluekeep Exploit::

   $ greynoise query "classification:malicious tags:Bluekeep Exploit"
   ╔═══════════════════════════╗
   ║       Query 1 of 1        ║
   ╚═══════════════════════════╝
   Query: classification:malicious tags:"Bluekeep Exploit"

   ┌───────────────────────────┐
   │      Result 1 of 20       │
   └───────────────────────────┘

             OVERVIEW
   ----------------------------
   Actor: unknown
   Classification: malicious
   First seen: 2018-12-10
   IP: 185.7.63.40
   Last seen: 2019-09-06
   Tags:
   - Web Crawler
   - Wordpress XML RPC Worm
   - RDP Scanner
   - Web Scanner
   - Bluekeep Exploit

             METADATA
   ----------------------------
   ASN: AS39783
   Category: hosting
   Location: Norway (NO)
   Organization: Rent a Rack AS
   OS: Windows XP
   rDNS: cp.netthost.no
   Tor: False

             RAW DATA
   ----------------------------
   [Scan]
   - Port/Proto: 80/TCP
   - Port/Proto: 3389/TCP

   [Paths]
   - /zabbix/toptriggers.php
   - /forum/xmlrpc.php
   - /wordpress/xmlrpc.php
   - /zabbix/jsrpc.php
   - /user/register/
   - /blog/xmlrpc.php
   - /xmlrpc.php
   - /wp/xmlrpc.php

.. note::

   This is the default command, that is, you can save some typing by just
   writing ``greynoise <query>`` instead of ``greynoise query <query>``.


Get statistics
~~~~~~~~~~~~~~

It's also possible to get statistics related to a GNQL query to better understand how
results are distributed in terms of different information such as organization, country,
operating system, etc.::

    $ greynoise stats 'classification:malicious tags:"Bluekeep Exploit"'
    ╔═══════════════════════════╗
    ║       Query 1 of 1        ║
    ╚═══════════════════════════╝
    Query: classification:malicious tags:"Bluekeep Exploit"

    ASNs:
    - AS16276  6
    - AS17621  3
    - AS14618  2
    - AS12083  1
    - AS14061  1
    - AS206264 1
    - AS206485 1
    - AS38895  1
    - AS39783  1
    - AS4134   1
    - AS45090  1
    - AS63949  1

    Categories:
    - hosting  12
    - isp       5
    - business  3

    Classifications:
    - malicious 20

    Countries:
    - Canada        5
    - China         5
    - United States 4
    - France        1
    - Germany       1
    - Lithuania     1
    - Netherlands   1
    - Norway        1
    - Singapore     1

    Operating systems:
    - Linux 3.11+ 9
    - Windows 7/8 3
    - Mac OS X    2
    - Windows XP  2

    Organizations:
    - OVH SAS                                           6
    - China Unicom Shanghai network                     3
    - Amazon.com, Inc.                                  2
    - Amarutu Technology Ltd                            1
    - Amazon.com Tech Telecom                           1
    - CHINANET-BACKBONE                                 1
    - DigitalOcean, LLC                                 1
    - Linode, LLC                                       1
    - Rent a Rack AS                                    1
    - Shenzhen Tencent Computer Systems Company Limited 1
    - UGB Hosting OU                                    1
    - WideOpenWest Finance LLC                          1

    Tags:
    - Bluekeep Exploit             20
    - RDP Scanner                  19
    - Web Scanner                  10
    - HTTP Alt Scanner              5
    - Ping Scanner                  5
    - SSH Scanner                   5
    - TLS/SSL Crawler               5
    - VNC Scanner                   5
    - DNS Scanner                   3
    - FTP Scanner                   3
    - IPSec VPN Scanner             3
    - SMB Scanner                   3
    - Web Crawler                   3
    - ZMap Client                   3
    - CPanel Scanner                2
    - CounterStrike Server Scanner  2
    - Elasticsearch Scanner         2
    - Ethereum Node Scanner         2
    - IMAP Scanner                  2
    - IOT MQTT Scanner              2
    Showing results 1 - 20. Run again with -v for full output

Community API Users
====================

The GreyNoise API and CLI components can both be used with the [GreyNoise Community API](https://developer.greynoise.io/reference/community-api).

The Community API only includes a single IP lookup endpoint, so only the IP lookup command in both the API and CLI components will work if enabled.

To enable Community API usage, do the following:

CLI Config File
---------------

::

    $ greynoise setup --api-key "<api_key>" --offering community
    Configuration saved to '/home/username/.config/greynoise/config'

    $ greynoise ip 192.223.30.35

    ╔═══════════════════════════╗
    ║     Community 1 of 1      ║
    ╚═══════════════════════════╝

    IP: 192.223.30.35
    NOISE: True
    RIOT: False
    Name: unknown
    Classification: unknown
    Last seen: 2021-03-18
    Link: https://viz.greynoise.io/ip/192.223.30.35


CLI IP Command
--------------

::

   $ greynoise ip <ip_address> --api-key "<api_key>" --offering community

API Client
----------

::

    $ api_client = GreyNoise(api_key=<api_key>, offering="community")
    $ api_client.ip('192.223.30.35')

    {
        'ip': '192.223.30.35',
        'noise': True,
        'riot': False,
        'classification': 'unknown',
        'name': 'unknown',
        'link': 'https://viz.greynoise.io/ip/192.223.30.35',
        'last_seen': '2021-03-18',
        'message': 'Success'
    }
