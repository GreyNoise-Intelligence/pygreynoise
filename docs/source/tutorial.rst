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

   >>> api_client.get_noise_status('8.8.8.8')
   
{"ip":"8.8.8.8","noise":false,"code":"0x05","code_message":"This IP is commonly spoofed in Internet-scan activity"}

When there's a list of IP addresses to verify, they can be checked all at once like
this::

   >>> client.get_noise_status_bulk(['8.8.8.8', '58.220.219.247'])

[{"ip":"8.8.8.8","noise":false,"code":"0x05","code_message":"This IP is commonly spoofed in Internet-scan activity"},{"ip":"58.220.219.247","noise":true,"code":"0x01","code_message":"The IP has been observed by the GreyNoise sensor network"}]

Detailed context information for any given IP address is also available::

   >>> api_client.get_context('58.220.219.247')

{"ip":"58.220.219.247","seen":true,"classification":"malicious","first_seen":"2019-04-04","last_seen":"2019-08-21","actor":"unknown","tags":["MSSQL Bruteforcer","MSSQL Scanner","RDP Scanner"],"metadata":{"country":"China","country_code":"CN","city":"Kunshan","organization":"CHINANET jiangsu province network","asn":"AS4134","tor":false,"os":"Windows 7/8","category":"isp"},"raw_data":{"scan":[{"port":1433,"protocol":"TCP"},{"port":3389,"protocol":"TCP"},{"port":65529,"protocol":"TCP"}],"web":{"paths":[],"useragents":[]},"ja3":[]}}


GNQL
----

Run a query
~~~~~~~~~~~

A GNQL (GreyNoise Query Language) query can be executed to dig deeper into the GreyNoise
dataset. For example, to get context information related to activity has been classified
as malicious and tagged as a Bluekeep Exploit::

   >>> api_client.run_query('classification:malicious tags:"Bluekeep Exploit"')

{"complete":true,"count":24,"data":[{"ip":"144.217.253.168","seen":true,"classification":"malicious","first_seen":"2019-06-04","last_seen":"2019-08-21","actor":"unknown","tags":["RDP Scanner","Bluekeep Exploit"],"metadata":{"country":"Canada","country_code":"CA","city":"Montréal","organization":"OVH SAS","rdns":"ns541387.ip-144-217-253.net","asn":"AS16276","tor":false,"os":"Linux 3.11+","category":"hosting"},"raw_data":{"scan":[{"port":3389,"protocol":"TCP"}],"web":{},"ja3":[]}},
   -- SNIP --
{"ip":"91.213.112.119","seen":true,"classification":"malicious","first_seen":"2019-04-18","last_seen":"2019-06-03","actor":"unknown","tags":["Bluekeep Exploit","RDP Scanner","TLS/SSL Crawler","Tor","VNC Scanner","Web Scanner","Windows RDP Cookie Hijacker CVE-2014-6318"],"metadata":{"country":"Netherlands","country_code":"NL","city":"","organization":"Onsweb B.V.","rdns":"no-reverse.onlinesystemen.nl","asn":"AS42755","tor":true,"os":"Linux 3.11+","category":"business"},"raw_data":{"scan":[{"port":443,"protocol":"TCP"},{"port":3389,"protocol":"TCP"},{"port":5900,"protocol":"TCP"}],"web":{},"ja3":[]}}],"message":"ok","query":"classification:malicious tags:'Bluekeep Exploit'"}


Get statistics
~~~~~~~~~~~~~~

It's also possible to get statistics related to a GNQL query to better understand how
results are distributed in terms of different information such as organization, country,
operating system, etc.:

   >>> api_client.run_stats_query('classification:malicious tags:"Bluekeep Exploit"')
   
{"query":"classification:malicious tags:'Bluekeep Exploit'","count":24,"stats":{"classifications":[{"classification":"malicious","count":24}],"organizations":[{"organization":"DigitalOcean, LLC","count":7},{"organization":"OVH SAS","count":6},{"organization":"China Unicom Shanghai network","count":3},{"organization":"Linode, LLC","count":3},{"organization":"Amarutu Technology Ltd","count":1},{"organization":"Amazon.com, Inc.","count":1},{"organization":"CHINANET-BACKBONE","count":1},{"organization":"INT-NETWORK","count":1},{"organization":"WideOpenWest Finance LLC","count":1}],"actors":null,"countries":[{"country":"Canada","count":6},{"country":"United States","count":6},{"country":"China","count":4},{"country":"Germany","count":3},{"country":"Netherlands","count":3},{"country":"France","count":1},{"country":"United Kingdom","count":1}],"tags":[{"tag":"Bluekeep Exploit","count":24},{"tag":"RDP Scanner","count":24},
   -- SNIP --
{"tag":"Telnet Scanner","count":1}],"operating_systems":[{"operating_system":"Linux 3.11+","count":16},{"operating_system":"Windows 7/8","count":3},{"operating_system":"Mac OS X","count":2},{"operating_system":"Linux 2.2-3.x","count":1}],"categories":[{"category":"hosting","count":17},{"category":"isp","count":6},{"category":"business","count":1}],"asns":[{"asn":"AS14061","count":7},{"asn":"AS16276","count":6},{"asn":"AS17621","count":3},{"asn":"AS63949","count":3},{"asn":"AS12083","count":1},{"asn":"AS14618","count":1},{"asn":"AS202425","count":1},{"asn":"AS206264","count":1},{"asn":"AS4134","count":1}]}}


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
   Configuration saved to '/home/username/.config/greynoise/config'

.. note::

   This is the default configuration method. Alternatively, the API key can be passed to every command using the *-k/--api-key* option
   or through the *GREYNOISE_API_KEY* environment variable.


Check specific IPs
------------------

Once the command line tool has been created, it's possible to check if a given IP is
considered internet noise or has been observed scanning or attacking devices across the
Internet as follows::

   $ greynoise ip quick-check 58.220.219.247
   58.220.219.247 is classified as NOISE.

When there's a list of IP addresses to verify, they can be checked all at once like
this::

   $ greynoise ip multi-quick-check 8.8.8.8 58.220.219.247
   8.8.8.8 is classified as NOT NOISE.
   58.220.219.247 is classified as NOISE.

Detailed context information for any given IP address is also available::

   $ greynoise ip context 58.220.219.247
 ┌───────────────────────────┐
 │       result 1 of 1       │
 └───────────────────────────┘

          OVERVIEW:
 ----------------------------
 IP: 58.220.219.247
 Classification: malicious
 First seen: 2019-07-04
 Last seen: 2019-08-21
 Actor: unknown
 Tags: ['RDP Scanner', 'MSSQL Scanner', 'MSSQL Bruteforcer']

          METADATA:
 ----------------------------
 Location: Kunshan, China (CN)
 Organization: CHINANET-BACKBONE
 ASN: AS4134
 OS: Windows 7/8
 Category: isp

          RAW DATA:
 ----------------------------
 Port/Proto: 1433/TCP
 Port/Proto: 3389/TCP
 Port/Proto: 65529/TCP
 

GNQL
----

Run a query
~~~~~~~~~~~

A GNQL (GreyNoise Query Language) query can be executed to dig deeper into the GreyNoise
dataset. For example, to get context information related to activity has been classified
as malicious and tagged as a Bluekeep Exploit::

   $ greynoise gnql query 'classification:malicious tags:"Bluekeep Exploit"'
 ┌───────────────────────────┐
 │       result 1 of 24      │
 └───────────────────────────┘

          OVERVIEW:
 ----------------------------
 IP: 144.217.253.168
 Classification: malicious
 First seen: 2019-06-04
 Last seen: 2019-08-21
 Actor: unknown
 Tags: ['RDP Scanner', 'Bluekeep Exploit']

          METADATA:
 ----------------------------
 Location: Montréal, Canada (CA)
 Organization: OVH SAS
 rDNS: ns541387.ip-144-217-253.net
 ASN: AS16276
 OS: Linux 3.11+
 Category: hosting

          RAW DATA:
 ----------------------------
 Port/Proto: 3389/TCP
 
 
.. note::

   This is the default command, that is, you can save some typing by just
   writing **greynoise <query>** instead of **greynose gnql query <query>**.


Get statistics
~~~~~~~~~~~~~~

It's also possible to get statistics related to a GNQL query to better understand how
results are distributed in terms of different information such as organization, country,
operating system, etc.::

   $ greynoise gnql stats 'classification:malicious tags:"Bluekeep Exploit"'
   ASNs:
   - AS14061: 7
   - AS16276: 6
   - AS17621: 3
   - AS63949: 3
   - AS12083: 1
   - AS14618: 1
   - AS202425: 1
   - AS206264: 1
   - AS4134: 1

   Categories:
   - hosting: 17
   - isp: 6
   - business: 1

   Classifications:
   - malicious: 24

   Countries:
   - Canada: 6
   - United States: 6
   - China: 4
   - Germany: 3
   - Netherlands: 3
   - France: 1
   - United Kingdom: 1

   Operating systems:
   - Linux 3.11+: 16
   - Windows 7/8: 3
   - Mac OS X: 2
   - Linux 2.2-3.x: 1

   Organizations:
   - DigitalOcean, LLC: 7
   - OVH SAS: 6
   - China Unicom Shanghai network: 3
   - Linode, LLC: 3
   - Amarutu Technology Ltd: 1
   - Amazon.com, Inc.: 1
   - CHINANET-BACKBONE: 1
   - INT-NETWORK: 1
   - WideOpenWest Finance LLC: 1

   Tags:
   - Bluekeep Exploit: 24
   - RDP Scanner: 24
   - ZMap Client: 9
   - DNS Scanner: 8
   - Web Scanner: 7
   - TLS/SSL Crawler: 6
   - HTTP Alt Scanner: 4
   - SSH Scanner: 4
   - VNC Scanner: 3
   - FTP Scanner: 2
   - Ping Scanner: 2
   - SMB Scanner: 2
   - SSH Bruteforcer: 2
   - Tor: 2
   - Web Crawler: 2
   - Bitcoin Node Scanner: 1
   - Bluekeep Scanner: 1
   - CPanel Scanner: 1
   - Cassandra Scanner: 1
   - CounterStrike Server Scanner: 1
   - Dockerd Scanner: 1
   - Elasticsearch Scanner: 1
   - IPSec VPN Scanner: 1
   - IRC Scanner: 1
   - LDAP Scanner: 1
   - MSSQL Scanner: 1
   - Masscan Client: 1
   - Minecraft Scanner: 1
   - MongoDB Scanner: 1
   - MySQL Scanner: 1
   - POP3 Scanner: 1
   - PPTP VPN Scanner: 1
   - Postgres Scanner: 1
   - Privoxy Proxy Scanner: 1
   - Python Requests Client: 1
   - RabbitMQ Scanner: 1
   - Redis Scanner: 1
   - SMTP Scanner: 1
   - SOCKS Proxy Scanner: 1
   - SSH Worm: 1
   - Telnet Scanner: 1

