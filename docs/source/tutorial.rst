========
Tutorial
========

API client
==========

Create client object
-------------------

To interact with the API, a client object needs to be created::

   >>> from greynoise.api import GreyNoise, APIConfig
   >>> api_config = APIConfig(
   ...     api_key=<api_key>,
   ...     timeout=<timeout_in_seconds>,
   ...     proxy=<proxy_url>,
   ...     use_cache=True,
   ...     cache_max_size=1000,
   ...     cache_ttl=3600,
   ...     integration_name=<name_of_integration>
   ... )
   >>> api_client = GreyNoise(api_config)

where:

* *api_key* is the key you have been given to use the API
* *timeout_in_seconds* is the timeout for each request sent to the API
* *proxy* is the url (ex ``http://myproxy.corp.io:1234``) for requests to be routed through
* *use_cache* is used to disable (enabled by default) use of local cache for lookups
* *cache_max_size* is used to define the max size of the cache, if enabled
* *cache_ttl* is used to define the TTL of the data in the cache, if enabled
* *integration_name* is used to define the name and version number of an integration that is embedding the SDK (example: ``greynoise-appname-v1.0.0``), if needed

.. note::

   All parameters are optional and might not be required if a
   configuration file has been created using the ``greynoise setup`` CLI command.

.. note::

   For third-parties developing integrations with the GreyNoise API, the integration_name parameter
   is preferred.


Check specific IPs
------------------

Once the client object has been created, it's possible to check if a given IP is
considered internet noise or has been observed scanning or attacking devices across the
Internet as follows::

    >>> api_client.quick('8.8.8.8')
    [{
      'ip': '8.8.8.8', 
      'business_service_intelligence': {
        'found': True, 
        'trust_level': '1'}, 
      'internet_scanner_intelligence': {
        'found': False, 
        'classification': ''}
    }]

When there's a list of IP addresses to verify, they can be checked all at once like
this::

    >>> api_client.quick(['64.39.111.185', '8.8.8.8', '108.168.3.151'])
    [
      {
        'ip': '64.39.111.185', 
        'business_service_intelligence': 
        {
          'found': True, 
          'trust_level': '1'
        }, 
        'internet_scanner_intelligence': 
        {
          'found': True, 
          'classification': 'benign'
        }
      }, 
      {
        'ip': '8.8.8.8', 
        'business_service_intelligence': {'found': True, 'trust_level': '1'}, 
        'internet_scanner_intelligence': {'found': False, 'classification': ''}
      }, {'ip': '108.168.3.151', 'business_service_intelligence': {'found': False, 'trust_level': ''}, 'internet_scanner_intelligence': {'found': False, 'classification': ''}}] 

When there's a list of IP addresses to verify, and invalid IPs provide should be included in the
output they can be checked all at once like this::

    >>> api_client.quick(['8.8.8.8', '58.220.219.247', '110.153.82.818'],include_invalid=True)
    [
      {
        'ip': '8.8.8.8', 
        'business_service_intelligence': 
        {
          'found': True, 
          'trust_level': '1'
        }, 
        'internet_scanner_intelligence': 
        {
          'found': False, 
          'classification': ''}
      }, 
      {
        'ip': '58.220.219.247', 
        'business_service_intelligence': 
        {
          'found': False, 
          'trust_level': ''
        }, 
        'internet_scanner_intelligence': 
        {
          'found': False, 
          'classification': ''
          }
        }, 
        {
          'ip': '110.153.82.818', 
          'business_service_intelligence': 
          {
            'found': False, 
            'trust_level': ''
          }, 
          'internet_scanner_intelligence': 
          {
            'found': False, 
            'classification': ''
            }
        }
    ]

Detailed context information for any given IP address is also available::

    >>> api_client.ip('91.133.151.207')
    {
        "ip": "91.133.151.207",
        "business_service_intelligence": {
            "found": False,
            "category": "",
            "name": "",
            "description": "",
            "explanation": "",
            "last_updated": "",
            "reference": "",
            "trust_level": ""
        },
        "internet_scanner_intelligence": {
            "first_seen": "2020-12-13",
            "last_seen": "2025-05-22",
            "found": True,
            "tags": [
                {
                    "id": "537cee16-c4a9-45cd-baf1-75963ab7bdd2",
                    "slug": "ssh-connection-attempt",
                    "name": "SSH Connection Attempt",
                    "description": "IP addresses with this tag have been observed attempting to negotiate an SSH session.",
                    "category": "activity",
                    "intention": "suspicious",
                    "references": [
                        "https://en.wikipedia.org/wiki/Secure_Shell"
                    ],
                    "cves": [],
                    "recommend_block": False,
                    "created": "2024-09-30",
                    "updated_at": "2025-05-22T16:16:17.454795Z"
                },
                {
                    "id": "869feaa1-dc77-4037-aee2-247b7a39cf7d",
                    "slug": "web-scanner",
                    "name": "Web Crawler",
                    "description": "IP addresses with this tag have been seen crawling HTTP(S) servers around the Internet.",
                    "category": "activity",
                    "intention": "unknown",
                    "references": [],
                    "cves": [],
                    "recommend_block": False,
                    "created": "2020-04-07",
                    "updated_at": "2025-05-22T16:16:19.258234Z"
                }
            ],
            "actor": "unknown",
            "spoofable": False,
            "classification": "suspicious",
            "cves": [],
            "bot": False,
            "vpn": False,
            "vpn_service": "",
            "tor": False,
            "metadata": {
                "asn": "AS197207",
                "source_country": "Iran",
                "source_country_code": "IR",
                "source_city": "Tehran",
                "domain": "mci.ir",
                "rdns_parent": "",
                "rdns_validated": False,
                "organization": "Mobile Communication Company of Iran PLC",
                "category": "isp",
                "rdns": "",
                "os": "",
                "sensor_count": 4,
                "sensor_hits": 126,
                "region": "Tehran",
                "mobile": True,
                "single_destination": False,
                "destination_countries": [
                    "India",
                    "Canada",
                    "United States"
                ],
                "destination_country_codes": [
                    "IN",
                    "CA",
                    "US"
                ],
                "destination_asns": [
                    "AS63949"
                ],
                "destination_cities": [
                    "Mumbai",
                    "Toronto",
                    "Fremont"
                ],
                "carrier": "IR-TCI (Hamrah-e-Avval)",
                "datacenter": "",
                "longitude": 51.4215,
                "latitude": 35.6944
            },
            "raw_data": {
                "scan": [
                    {
                        "port": 22,
                        "protocol": "tcp"
                    },
                    {
                        "port": 53,
                        "protocol": "tcp"
                    },
                    {
                        "port": 80,
                        "protocol": "tcp"
                    },
                    {
                        "port": 409,
                        "protocol": "tcp"
                    },
                    {
                        "port": 796,
                        "protocol": "tcp"
                    },
                    {
                        "port": 409,
                        "protocol": "udp"
                    }
                ],
                "ja3": [],
                "hassh": [],
                "http": {
                    "md5": [
                        "c7afa74cef7c752d89b971d9241d2b6b",
                        "690e440f039d37e8098f20406f460c11",
                        "2f425337f87e0c4432b7153ce312711f",
                        "890472785806b63928cec283b1776d3a",
                        "5308981d069a66feb6694cbcc754fce1"
                    ],
                    "cookie_keys": [
                        "netnet",
                        "S"
                    ],
                    "request_authorization": [],
                    "request_cookies": [
                        "netnet=8UPm4GgeZUalxo4oNCmLSO0ouclTypqsmS51a8YL4ccE1g4/rcWXjfctCvc/yx16dBhlBHM0ccSWcBvGdxzZYaGIshDxtZEbVas5LYWnAiBYBjpIb9YxpxLOYy40Z4E8SelOLnXi9PhJfvZNYdSLm10F5yRlFl6YXTqgijVXGtetBhBa6VFfTEVUK4KeHu9hWlb0LWNCJgvEtNeKIGx/cgElPBiUh6lo9wfb8len4i8qx6P1Y4/BnnQoyz6+5UUD0+8F7q2OS+SPfNAXMqkygfwLfs70NCI50S4PNLGxkn8i1Ed7Xt+XlaMlbr8H88hi/fF5rnwFmvZonwwmPe1M/qqtBse7WZp0Zgo3AxA5SBKISTRnQGX6BAYa2u/EcwVEVdq3UDx6e19lqSvvIsVYeDj9wOWOSyuMXjI3DjRtqmd8U0auDz9QRl9d2SsGVT5MZM6vRmOh2U7jtGRFD3ROGhAmqck=",
                        "S=QIpOdjth6toeF8mYwDYQ7msD9qExCFuGUi610lQ/O9+vorMKp9nfVtrpiigK8WyiDzPGvxiEtTCfYIDBp+9ZUBZ7XMNIamgHHcLEfsrZYtEvlyxezxJlECkMhoY1wvIG8TdXkkDZKFvST/ldzXFzoD7v1z0wkUFu0bfuO3TEHecFRu30apkaGu7styRGC+PNk9Yyn+g1BIIp8MXheBmLecuWpfdT+AqgwH0VFyVOLKML/IW+hFCBHCXAcX+EnDgwooGPnthRqKT+0aiOSWV/H0347m8="
                    ],
                    "request_header": [
                        "content-type",
                        "host",
                        "content-length",
                        "cookie",
                        "accept-encoding"
                    ],
                    "method": [
                        "POST"
                    ],
                    "path": [
                        "/"
                    ],
                    "request_origin": [],
                    "useragent": []
                },
                "source": {
                    "bytes": 42960
                },
                "tls": {
                    "cipher": [],
                    "ja4": []
                },
                "ssh": {
                    "key": []
                }
            },
            "last_seen_timestamp": "2025-05-22 05:40:41"
        },
        "request_metadata": {
            "restricted_fields": []
        }
    }

When there's a list of IP addresses to get full context from, they can be checked all at once like
this (this method also supports the include_invalid flag::

    >>> api_client.ip_multi(['8.8.8.8', '58.220.219.247'])
    [
      {
        "ip": "8.8.8.8",
        "business_service_intelligence": {
          "found": true,
          "category": "public_dns",
          "name": "Google Public DNS",
          "description": "Google's global domain name system (DNS) resolution service.",
          "explanation": "Public DNS services are used as alternatives to ISP's name servers. You may see devices on your network communicating with Google Public DNS over port 53/TCP or 53/UDP to resolve DNS lookups.",
          "last_updated": "2025-05-23T13:11:02Z",
          "reference": "https://developers.google.com/speed/public-dns/docs/isp#alternative",
          "trust_level": "1"
        },
        "internet_scanner_intelligence": {
          "first_seen": "",
          "last_seen": "",
          "found": false,
          "tags": [],
          "actor": "",
          "spoofable": false,
          "classification": "",
          "cves": [],
          "bot": false,
          "vpn": false,
          "vpn_service": "",
          "tor": false,
          "metadata": {
            "asn": "",
            "source_country": "",
            "source_country_code": "",
            "source_city": "",
            "domain": "",
            "rdns_parent": "",
            "rdns_validated": false,
            "organization": "",
            "category": "",
            "rdns": "",
            "os": "",
            "sensor_count": 0,
            "sensor_hits": 0,
            "region": "",
            "mobile": false,
            "single_destination": false,
            "destination_countries": [],
            "destination_country_codes": [],
            "destination_asns": [],
            "destination_cities": [],
            "carrier": "",
            "datacenter": "",
            "longitude": 0,
            "latitude": 0
          },
          "raw_data": {
            "scan": [],
            "ja3": [],
            "hassh": [],
            "http": {
              "md5": [],
              "cookie_keys": [],
              "request_authorization": [],
              "request_cookies": [],
              "request_header": [],
              "method": [],
              "path": [],
              "request_origin": [],
              "useragent": []
            },
            "source": {
              "bytes": 0
            },
            "tls": {
              "cipher": [],
              "ja4": []
            },
            "ssh": {
              "key": []
            }
          },
          "last_seen_timestamp": "",
          "request_metadata": {
            "restricted_fields": []
          }
        }
      },
      {
        "ip": "58.220.219.247",
        "business_service_intelligence": {
          "found": false,
          "trust_level": ""
        },
        "internet_scanner_intelligence": {
          "found": false,
          "classification": ""
        }
      }
    ]

Any IP can also be checked to see if there are any Similar IPs in the Noise Dataset::

    >>> api_client.similar('45.83.66.65')
    {
       "ip":{
          "ip":"45.83.66.65",
          "actor":"Alpha Strike Labs",
          "classification":"benign",
          "first_seen":"2019-07-12",
          "last_seen":"2022-11-09",
          "asn":"AS208843",
          "city":"Berlin",
          "country":"Germany",
          "country_code":"DE",
          "organization":"Alpha Strike Labs GmbH"
       },
       "similar_ips":[
          {
             "ip":"45.83.66.68",
             "score":0.9628107,
             "features":[
                "ja3_fp",
                "mass_scan_bool",
                "os",
                "ports",
                "useragents",
                "web_paths"
             ],
             "actor":"Alpha Strike Labs",
             "classification":"benign",
             "first_seen":"2019-07-12",
             "last_seen":"2022-11-09",
             "asn":"AS208843",
             "city":"Berlin",
             "country":"Germany",
             "country_code":"DE",
             "organization":"Alpha Strike Labs GmbH"
          }
       ],
       "total":1275
    }

.. note::

    The ``ip`` and ``quick`` methods use an LRU cache with a timeout of one hour to
    return faster responses in case the same addresses are queried multiple times. It
    can be disabled to get live responses from the API by passing ``use_cache=False``
    when the ``GreyNoise`` class is instantiated.

Sample Python Code
------------------

.. include:: sample.py

GNQL
----

Run a query
~~~~~~~~~~~

A GNQL (GreyNoise Query Language) query can be executed to dig deeper into the GreyNoise
dataset. For example, to get context information related to activity has been classified
as malicious and tagged as a Bluekeep Exploit::

    >>> api_client.query('last_seen:1d classification:"suspicious" actor:"NiceCrawler"')
    {
      "data": [
        {
          "ip": "69.160.160.55",
          "business_service_intelligence": {
            "found": false,
            "category": "",
            "name": "",
            "description": "",
            "explanation": "",
            "last_updated": "",
            "reference": "",
            "trust_level": ""
          },
          "internet_scanner_intelligence": {
            "first_seen": "2021-05-19",
            "last_seen": "2025-05-22",
            "found": true,
            "tags": [
              {
                "id": "79f609f0-4d07-455d-b9b1-56ff7c1a77a9",
                "slug": "carries-http-referer-scanner",
                "name": "Carries HTTP Referer",
                "description": "IP addresses with this tag have been observed scanning the internet with an HTTP client that includes the Referer header in their requests.",
                "category": "activity",
                "intention": "suspicious",
                "references": [
                  "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referer"
                ],
                "cves": [],
                "recommend_block": false,
                "created": "2021-08-19",
                "updated_at": "2025-05-22T16:16:04.690597Z"
              },
              {
                "id": "7a184ad1-f150-42d2-86c9-a83180dd1a8d",
                "slug": "nicecrawler",
                "name": "NiceCrawler",
                "description": "IP addresses with this tag belong NiceCrawler, a crawler archiving the internet.",
                "category": "actor",
                "intention": "unknown",
                "references": [
                  "https://nicecrawler.com/"
                ],
                "cves": [],
                "recommend_block": false,
                "created": "2023-03-29",
                "updated_at": "2025-05-22T16:16:01.227892Z"
              },
              {
                "id": "869feaa1-dc77-4037-aee2-247b7a39cf7d",
                "slug": "web-scanner",
                "name": "Web Crawler",
                "description": "IP addresses with this tag have been seen crawling HTTP(S) servers around the Internet.",
                "category": "activity",
                "intention": "unknown",
                "references": [],
                "cves": [],
                "recommend_block": false,
                "created": "2020-04-07",
                "updated_at": "2025-05-22T16:16:19.258234Z"
              }
            ],
            "actor": "NiceCrawler",
            "spoofable": false,
            "classification": "suspicious",
            "cves": [],
            "bot": false,
            "vpn": false,
            "vpn_service": "",
            "tor": false,
            "metadata": {
              "asn": "AS22772",
              "source_country": "United States",
              "source_country_code": "US",
              "source_city": "Tucson",
              "domain": "loginbusiness.com",
              "rdns_parent": "nicecrawler.com",
              "rdns_validated": false,
              "organization": "Login, Inc.",
              "category": "hosting",
              "rdns": "crawler-55.nicecrawler.com",
              "os": "",
              "sensor_count": 3,
              "sensor_hits": 38,
              "region": "Arizona",
              "mobile": false,
              "single_destination": false,
              "destination_countries": [
                "United States",
                "Portugal"
              ],
              "destination_country_codes": [
                "US",
                "PT"
              ],
              "destination_asns": [
                "AS20473",
                "AS44477",
                "AS63949"
              ],
              "destination_cities": [
                "Braga",
                "Fremont",
                "Piscataway"
              ],
              "carrier": "",
              "datacenter": "",
              "longitude": -110.9694,
              "latitude": 32.2139
            },
            "raw_data": {
              "scan": [
                {
                  "port": 80,
                  "protocol": "tcp"
                }
              ],
              "ja3": [],
              "hassh": [],
              "http": {
                "md5": [
                  "690e440f039d37e8098f20406f460c11"
                ],
                "cookie_keys": [],
                "request_authorization": [],
                "request_cookies": [],
                "request_header": [
                  "referer",
                  "accept-language",
                  "cache-control",
                  "connection",
                  "accept",
                  "accept-charset",
                  "accept-encoding",
                  "user-agent",
                  "host",
                  "upgrade-insecure-requests"
                ],
                "method": [
                  "GET"
                ],
                "path": [
                  "/"
                ],
                "request_origin": [],
                "useragent": [
                  "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; Nicecrawler/1.1; +http://www.nicecrawler.com/) Chrome/90.0.4430.97 Safari/537.36",
                  "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/81.0.4044.92 Safari/537.36"
                ]
              },
              "source": {
                "bytes": 4588
              },
              "tls": {
                "cipher": [],
                "ja4": []
              },
              "ssh": {
                "key": []
              }
            },
            "last_seen_timestamp": "2025-05-22 22:07:15"
          }
        }
      ],
      "request_metadata": {
        "restricted_fields": [],
        "message": "",
        "query": "last_seen:1d classification:\"suspicious\" actor:\"NiceCrawler\"",
        "complete": true,
        "count": 1
      }
    }


Get statistics
~~~~~~~~~~~~~~

It's also possible to get statistics related to a GNQL query to better understand how
results are distributed in terms of different information such as organization, country,
operating system, etc.::

    >>> api_client.stats('last_seen:1d classification:"suspicious" actor:"NiceCrawler"')
    {
      "count": 1,
      "query": "last_seen:1d classification:\"suspicious\" actor:\"NiceCrawler\"",
      "adjusted_query": "",
      "stats": {
        "classifications": [
          {
            "classification": "suspicious",
            "count": 1
          }
        ],
        "spoofable": [
          {
            "spoofable": false,
            "count": 1
          }
        ],
        "organizations": [
          {
            "organization": "Login, Inc.",
            "count": 1
          }
        ],
        "actors": [
          {
            "actor": "NiceCrawler",
            "count": 1
          }
        ],
        "countries": [
          {
            "country": "United States",
            "count": 1
          }
        ],
        "source_countries": [
          {
            "country": "United States",
            "count": 1
          }
        ],
        "destination_countries": [
          {
            "country": "Portugal",
            "count": 1
          },
          {
            "country": "United States",
            "count": 1
          }
        ],
        "tags": [
          {
            "tag": "Carries HTTP Referer",
            "id": "79f609f0-4d07-455d-b9b1-56ff7c1a77a9",
            "count": 1
          },
          {
            "tag": "NiceCrawler",
            "id": "7a184ad1-f150-42d2-86c9-a83180dd1a8d",
            "count": 1
          },
          {
            "tag": "Web Crawler",
            "id": "869feaa1-dc77-4037-aee2-247b7a39cf7d",
            "count": 1
          }
        ],
        "operating_systems": null,
        "categories": [
          {
            "category": "hosting",
            "count": 1
          }
        ],
        "asns": [
          {
            "asn": "AS22772",
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
      account          View information about your GreyNoise account.
      alerts           List, create, delete, and manage your GreyNoise alerts.
      analyze          Analyze the IP addresses in a log file, stdin, etc.
      cve              Retrieve Details of a CVE.
      feedback         Send feedback directly to the GreyNoise team.
      filter           Filter the noise from a log file, stdin, etc.
      help             Show this message and exit.
      ip               Query GreyNoise for all information on a given IP.
      ip-multi         Perform Context lookup for multiple IPs at once.
      persona-details  Retrieve Details of a Sensor Persona.
      query            Run a GNQL (GreyNoise Query Language) query.
      quick            Quickly check whether or not one or many IPs are "noise".
      repl             Start an interactive shell.
      riot             Query GreyNoise IP to see if it is in the RIOT dataset.
      sensor-activity  Retrieve Sensor Activity.
      sensor-list      Retrieve list of current Sensors in Workspace.
      setup            Configure API client.
      signature        Submit an IDS signature to GreyNoise to be deployed to...
      similar          Query GreyNoise IP to identify Similar IPs.
      stats            Get aggregate stats from a given GNQL query.
      timeline         Query GreyNoise IP Timeline for events based on a...
      timelinedaily    Query GreyNoise IP Timeline to get daily event details.
      timelinehourly   Query GreyNoise IP Timeline to get hourly event details.
      version          Get version and OS information for your GreyNoise...


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

   $ greynoise quick 69.160.160.55
    69.160.160.55 is identified as NOISE and is classified as suspicious.

When there's a list of IP addresses to verify, they can be checked all at once like
this (a comma separated list is also supported::

   $ greynoise quick 69.160.160.55,8.8.8.8
    69.160.160.55 is identified as NOISE and is classified as suspicious.
    8.8.8.8 is part of RIOT and is Trust Level 1.

Detailed context information for any given IP address is also available::

   $ greynoise ip 69.160.160.55
    ╔═══════════════════════════╗
    ║      Context 1 of 1       ║
    ╚═══════════════════════════╝
    IP address: 69.160.160.55


              Internet Scanner Intelligence
    -----------------------------------------------
    IP: 69.160.160.55
    Actor: NiceCrawler
    Classification: suspicious
    First Seen: 2021-05-19
    Last Seen: 2025-05-22 22:07:15
    Spoofable: False
    BOT: False
    VPN: False
    TOR: False
    [TAGS]
    - Carries HTTP Referer
    - NiceCrawler
    - Web Crawler


              METADATA
    ----------------------------
    ASN: AS22772
    Category: hosting
    Source Location: Tucson, United States (US)
    Destination Countries: United States, Portugal
    Region: Arizona
    Organization: Login, Inc.
    rDNS: crawler-55.nicecrawler.com

              RAW DATA
    ----------------------------
    [Scan]
    - Port/Proto: 80/tcp

    [Paths]
    - /

    [Useragents]
    - Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; Nicecrawler/1.1; +http://www.nicecrawler.com/) Chrome/90.0.4430.97 Safari/537.36
    - Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/81.0.4044.92 Safari/537.36


When there's a list of IP addresses to verify, they can be checked all at once like
this (a comma separated list is also supported::

   $ greynoise ip-multi 69.160.160.55,8.8.8.8

    ╔═══════════════════════════╗
    ║      Context 1 of 2       ║
    ╚═══════════════════════════╝
    IP address: 69.160.160.55


              Internet Scanner Intelligence
    -----------------------------------------------
    IP: 69.160.160.55
    Actor: NiceCrawler
    Classification: suspicious
    First Seen: 2021-05-19
    Last Seen: 2025-05-22 22:07:15
    Spoofable: False
    BOT: False
    VPN: False
    TOR: False
    [TAGS]
    - Carries HTTP Referer
    - NiceCrawler
    - Web Crawler


              METADATA
    ----------------------------
    ASN: AS22772
    Category: hosting
    Source Location: 
    Destination Countries: United States, Portugal
    Region: Arizona
    Organization: Login, Inc.
    rDNS: crawler-55.nicecrawler.com

              RAW DATA
    ----------------------------
    [Scan]
    - Port/Proto: 80/tcp

    [Paths]
    - /

    [Useragents]
    - Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; Nicecrawler/1.1; +http://www.nicecrawler.com/) Chrome/90.0.4430.97 Safari/537.36
    - Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/81.0.4044.92 Safari/537.36


    ╔═══════════════════════════╗
    ║      Context 2 of 2       ║
    ╚═══════════════════════════╝
    IP address: 8.8.8.8


              Business Service Intelligence
    -----------------------------------------------
    IP: 8.8.8.8
    RIOT: True
    Category: public_dns
    Trust Level: 1
    Name: Google Public DNS
    Description: Google's global domain name system (DNS) resolution service.
    Explanation: Public DNS services are used as alternatives to ISP's name servers. You may see devices on your network communicating with Google Public DNS over port 53/TCP or 53/UDP to resolve DNS lookups.
    Last Updated: 2025-05-23T13:11:02Z
    Reference: https://developers.google.com/speed/public-dns/docs/isp#alternative

Check for Similar IPs to a given IP::

   $ greynoise similar 69.160.160.55

             IP Similarity Source
          --------------------
      IP: 69.160.160.55
      Actor: NiceCrawler
      Classification: unknown
      First Seen: 2021-05-19
      Last Seen: 2024-10-12
      ASN: AS22772
      City: Tucson
      Country: United States
      Country Code: US
      Organization: Login, Inc.
      Total: 118

                IP Similarity - Top 25 Results
                -------------------------------
      IP             Score          Classification   Actor                    Last Seen      Organization             Features Matched    
      45.157.183.37  0.92512727                                               0001-01-01                              bot_bool, ports, useragents, web_paths
      14.233.204.146 0.9240097      malicious        unknown                  2019-06-28     Vietnam Posts and Telecommunications Groupbot_bool, ports, useragents, web_paths
      84.32.41.136   0.9239762      unknown          unknown                  2024-10-22     HOSTGNOME LTD            bot_bool, ports, useragents, web_paths
      93.158.92.11   0.92302084     unknown          unknown                  2024-09-23     GlobalConnect AB         bot_bool, ports, useragents, web_paths
      44.244.71.83   0.92279327                                               0001-01-01                              bot_bool, ports, useragents, web_paths
      89.117.72.173  0.92242795                                               0001-01-01                              bot_bool, ports, useragents, web_paths
      47.82.10.151   0.9213447                                                0001-01-01                              bot_bool, ports, useragents, web_paths
      47.82.10.174   0.9213447                                                0001-01-01                              bot_bool, ports, useragents, web_paths
      47.82.10.229   0.9213447                                                0001-01-01                              bot_bool, ports, useragents, web_paths
      47.82.11.251   0.9213447                                                0001-01-01                              bot_bool, ports, useragents, web_paths
      47.82.11.76    0.9213447                                                0001-01-01                              bot_bool, ports, useragents, web_paths
      47.82.11.88    0.9213447                                                0001-01-01                              bot_bool, ports, useragents, web_paths
      167.172.20.109 0.9171009      unknown          unknown                  2024-09-08     DigitalOcean, LLC        bot_bool, ports, useragents, web_paths
      193.34.74.99   0.916965                                                 0001-01-01                              bot_bool, ports, useragents, web_paths
      64.43.110.168  0.916965                                                 0001-01-01                              bot_bool, ports, useragents, web_paths
      64.43.110.46   0.916965                                                 0001-01-01                              bot_bool, ports, useragents, web_paths
      64.43.117.78   0.916965                                                 0001-01-01                              bot_bool, ports, useragents, web_paths
      199.244.88.221 0.91685367     unknown          unknown                  2024-10-23     Sundance International LLCbot_bool, ports, useragents, web_paths
      199.244.88.231 0.91685367     unknown          unknown                  2024-10-24     Sundance International LLCbot_bool, ports, useragents, web_paths
      203.177.94.114 0.91523826                                               0001-01-01                              bot_bool, ports, useragents, web_paths
      204.12.231.186 0.91523826                                               0001-01-01                              bot_bool, ports, useragents, web_paths
      20.245.238.242 0.91384023                                               0001-01-01                              bot_bool, ports, useragents, web_paths
      18.236.204.122 0.91345936                                               0001-01-01                              bot_bool, ports, useragents, web_paths
      54.218.240.44  0.91345936                                               0001-01-01                              bot_bool, ports, useragents, web_paths
      194.31.173.201 0.9130445      unknown          unknown                  2024-10-18     TimeWeb Ltd.             bot_bool, ports, useragents, web_paths

Check the Timeline of a given IP::

   $ greynoise timeline 69.160.160.55 -d 30 
   
          IP Timeline - Single Attribute
          ------------------------------
      IP: 69.160.160.55
      Field: classification
      Start: 2025-04-23
      End: 2025-05-23
      Granularity: 1d

                Timeline
                --------
      Timestamp      Event Count    Classification 
      2025-05-22     1              suspicious     
      2025-05-11     1              suspicious     
      2025-04-27     1              suspicious     

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
