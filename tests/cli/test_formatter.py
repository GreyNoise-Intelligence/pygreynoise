# coding=utf-8
"""Formatter test cases."""

import textwrap

import pytest

from greynoise.cli.formatter import (
    ANSI_MARKUP,
    gnql_query_formatter,
    gnql_stats_formatter,
    ip_context_formatter,
    ip_quick_check_formatter,
    json_formatter,
    riot_formatter,
    xml_formatter,
)

EXAMPLE_IP_CONTEXT = {
    "ip": "<ip_address>",
    "internet_scanner_intelligence": {
        "found": True,
        "actor": "<actor>",
        "bot": False,
        "classification": "<classification>",
        "cves": ["<cve#1>", "<cve#2>"],
        "first_seen": "<first_seen>",
        "last_seen_timestamp": "<last_seen>",
        "tor": False,
        "metadata": {
            "asn": "<asn>",
            "category": "<category>",
            "city": "<city>",
            "country": "<country>",
            "country_code": "<country_code>",
            "source_city": "<source_city>",
            "source_country": "<source_country>",
            "source_country_code": "<source_country_code>",
            "destination_countries": ["<dest_country_1>", "<dest_country_2>"],
            "destination_country_codes": [
                "<dest_country_code_1>",
                "<dest_country_code_2>",
            ],
            "organization": "<organization>",
            "os": "<os>",
            "region": "<region>",
            "rdns": "<rdns>",
        },
        "raw_data": {
            "hassh": [
                {"fingerprint": "<hassh#1>", "port": 123456},
                {"fingerprint": "<hassh#2>", "port": 123456},
                {"fingerprint": "<hassh#3>", "port": 123456},
            ],
            "ja3": [
                {"fingerprint": "<fingerprint#1>", "port": 123456},
                {"fingerprint": "<fingerprint#2>", "port": 123456},
                {"fingerprint": "<fingerprint#3>", "port": 123456},
            ],
            "scan": [
                {"port": 123456, "protocol": "TCP"},
                {"port": 123456, "protocol": "UDP"},
            ],
            "http": {
                "path": ["/", "/favicon.ico", "/robots.txt"],
                "useragent": ["<useragent#1>", "<useragent#2>", "<useragent#3>"],
            },
            "tls": {"ja4": ["test-ja4"]},
        },
        "seen": True,
        "spoofable": False,
        "tags": [{"name": "<tag#1>"}, {"name": "<tag#2>"}, {"name": "<tag#3>"}],
        "vpn": False,
        "vpn_service": "",
    },
    "business_service_intelligence": {
        "found": False,
    },
}

EXAMPLE_IP_CONTEXT_OUTPUT = ANSI_MARKUP.parse(
    textwrap.dedent(
        """\
                  <header>Internet Scanner Intelligence</header>
        -----------------------------------------------
        <key>IP</key>: <value><ip_address></value>
        <key>Actor</key>: <value><actor></value>
        <key>Classification</key>: <value><classification></value>
        <key>First Seen</key>: <value><first_seen></value>
        <key>Last Seen</key>: <value><last_seen></value>
        <key>Spoofable</key>: <value>False</value>
        <key>BOT</key>: <value>False</value>
        <key>VPN</key>: <value>False</value>
        <key>TOR</key>: <value>False</value>
        [TAGS]
        - <value><tag#1></value>
        - <value><tag#2></value>
        - <value><tag#3></value>

        
                  <header>METADATA</header>
        ----------------------------
        <key>ASN</key>: <value><asn></value>
        <key>Category</key>: <value><category></value>
        <key>Source Location</key>: <value><source_city>, <source_country> (<source_country_code>)</value>
        <key>Destination Countries</key>: <value><dest_country_1>, <dest_country_2></value>
        <key>Region</key>: <value><region></value>
        <key>Organization</key>: <value><organization></value>
        <key>OS</key>: <value><os></value>
        <key>rDNS</key>: <value><rdns></value>

                  <header>RAW DATA</header>
        ----------------------------
        [CVEs]
        - <value><cve#1></value>
        - <value><cve#2></value>

        [Scan]
        - <key>Port/Proto</key>: <value>123456/TCP</value>
        - <key>Port/Proto</key>: <value>123456/UDP</value>

        [Paths]
        - <value>/</value>
        - <value>/favicon.ico</value>
        - <value>/robots.txt</value>

        [Useragents]
        - <value><useragent#1></value>
        - <value><useragent#2></value>
        - <value><useragent#3></value>

        [JA3]
        - <key>Port</key>: <value>123456</value>, <key>Fingerprint</key>: <value><fingerprint#1></value>
        - <key>Port</key>: <value>123456</value>, <key>Fingerprint</key>: <value><fingerprint#2></value>
        - <key>Port</key>: <value>123456</value>, <key>Fingerprint</key>: <value><fingerprint#3></value>

        [JA4]
        - <value>test-ja4</value>

        [HASSH]
        - <key>Port</key>: <value>123456</value>, <key>Fingerprint</key>: <value><hassh#1></value>
        - <key>Port</key>: <value>123456</value>, <key>Fingerprint</key>: <value><hassh#2></value>
        - <key>Port</key>: <value>123456</value>, <key>Fingerprint</key>: <value><hassh#3></value>"""  # noqa
    )
)


class TestJSONFormatter(object):
    """JSON formatter tests."""

    def test_json_format(self):
        """Format to json."""
        assert json_formatter({"a": "result"}, _verbose=False) == textwrap.dedent(
            """\
            {
                "a": "result"
            }"""
        )


class TestXMLFormatter(object):
    """XML formatter tests."""

    def test_xml_format(self):
        """Format to xml."""
        assert xml_formatter({"a": "result"}, _verbose=False) == textwrap.dedent(
            """\
            <?xml version="1.0" ?>
            <root>
               <a>result</a>
            </root>"""
        )


class TestIPContextFormatter:
    """Test IP context formatter."""

    @pytest.mark.parametrize(
        "result, expected",
        (
            (
                [
                    EXAMPLE_IP_CONTEXT,
                    {
                        "error": "commonly spoofed ip",
                        "ip": "<ip_address#2>",
                        "internet_scanner_intelligence": {"found": False},
                        "business_service_intelligence": {"found": False},
                    },
                    {
                        "ip": "<ip_address#3>",
                        "internet_scanner_intelligence": {"found": False},
                        "business_service_intelligence": {"found": False},
                    },
                ],
                ANSI_MARKUP.parse(
                    textwrap.dedent(
                        """\
                        ╔═══════════════════════════╗
                        ║ <header>     Context 1 of 3      </header> ║
                        ╚═══════════════════════════╝
                        IP address: <ip_address>


                        """
                    )
                )
                + EXAMPLE_IP_CONTEXT_OUTPUT
                + ANSI_MARKUP.parse(
                    textwrap.dedent(
                        """




                        ╔═══════════════════════════╗
                        ║ <header>     Context 2 of 3      </header> ║
                        ╚═══════════════════════════╝
                        IP address: <ip_address#2>

                        <ip_address#2> has not been seen in scans in the past 90 days.


                        ╔═══════════════════════════╗
                        ║ <header>     Context 3 of 3      </header> ║
                        ╚═══════════════════════════╝
                        IP address: <ip_address#3>

                        <ip_address#3> has not been seen in scans in the past 90 days."""  # noqa
                    )
                ),
            ),
        ),
    )
    def test_format_ip_context(self, result, expected):
        """Format IP context."""
        assert ip_context_formatter(result, verbose=False).strip("\n") == expected


class TestIPQuickCheckFormatter:
    """Test IP quick check formatter."""

    @pytest.mark.parametrize(
        "result, expected",
        (
            (
                [
                    {
                        "ip": "0.0.0.0",
                        "internet_scanner_intelligence": {
                            "found": True,
                            "classification": "noise",
                        },
                        "business_service_intelligence": {"found": False},
                    }
                ],
                ANSI_MARKUP.parse(
                    "<noise>0.0.0.0</noise> is identified as <bold>"
                    "<red>NOISE</red></bold> and is classified as <green>noise</green>."
                ),
            ),
            (
                [
                    {
                        "ip": "0.0.0.0",
                        "internet_scanner_intelligence": {
                            "found": False,
                            "classification": "not-noise",
                        },
                        "business_service_intelligence": {"found": False},
                    }
                ],
                ANSI_MARKUP.parse(
                    "<not-noise>0.0.0.0</not-noise> is classified as <bold>"
                    "NOT NOISE</bold>."
                ),
            ),
        ),
    )
    def test_format_ip_quick_check(self, result, expected):
        """Format IP quick check."""
        assert ip_quick_check_formatter(result, verbose=False).strip("\n") == expected


class TestGNQLQueryFormatter(object):
    """GNQL query formatter tests."""

    @pytest.mark.parametrize(
        "result, expected",
        (
            (
                [
                    {
                        "data": [EXAMPLE_IP_CONTEXT],
                        "request_metadata": {
                            "restricted_fields": [],
                            "message": "",
                            "query": "<ip_address>",
                            "count": 1,
                            "scroll": "abcdefg",
                            "complete": True,
                            "adjusted_query": "",
                        },
                    }
                ],
                ANSI_MARKUP.parse(
                    textwrap.dedent(
                        """\
                        ╔═══════════════════════════╗
                        ║ <header>      Query 1 of 1       </header> ║
                        ╚═══════════════════════════╝
                        Query: <ip_address>
                        Count of IPs Returned: 1
                        Scroll Token: abcdefg

                        ┌───────────────────────────┐
                        │       Result 1 of 1       │
                        └───────────────────────────┘


                    """
                    )
                )
                + EXAMPLE_IP_CONTEXT_OUTPUT,
            ),
        ),
    )
    def test_format_gnql_query(self, result, expected):
        """Format GNQL query."""
        actual = gnql_query_formatter(result, verbose=False).strip("\n")
        print("\nActual output:")
        print(actual)
        print("\nExpected output:")
        print(expected)
        assert actual == expected


class TestGNQLStatsFormatter(object):
    """GNQL formatter tests."""

    @pytest.mark.parametrize(
        "result, expected",
        (
            (
                [
                    {
                        "count": 2,
                        "query": "<ip_address>",
                        "stats": {
                            "actors": [
                                {"actor": "<actor>", "count": 1},
                                {"actor": "<long_actor>", "count": 1},
                            ],
                            "asns": [
                                {"asn": "<asn>", "count": 1},
                                {"asn": "<long_asn>", "count": 1},
                            ],
                            "categories": [
                                {"category": "<category>", "count": 1},
                                {"category": "<long_category>", "count": 1},
                            ],
                            "classifications": [
                                {"classification": "<classification>", "count": 1},
                                {"classification": "<long_classification>", "count": 1},
                            ],
                            "countries": [
                                {"country": "<country>", "count": 1},
                                {"country": "<long_country>", "count": 1},
                            ],
                            "destination_countries": [
                                {"country": "<country>", "count": 1},
                                {"country": "<long_country>", "count": 1},
                            ],
                            "operating_systems": [
                                {"operating_system": "<operating_system>", "count": 1},
                                {
                                    "operating_system": "<long_operating_system>",
                                    "count": 1,
                                },
                            ],
                            "organizations": [
                                {"organization": "<organization>", "count": 1},
                                {"organization": "<long_organization>", "count": 1},
                            ],
                            "source_countries": [
                                {"country": "<country>", "count": 1},
                                {"country": "<long_country>", "count": 1},
                            ],
                            "spoofable": [
                                {"spoofable": "<spoofable>", "count": 1},
                                {"spoofable": "<spoofable>", "count": 1},
                            ],
                            "tags": [
                                {"tag": "<tag>", "count": 1},
                                {"tag": "<long_tag>", "count": 1},
                            ],
                        },
                    }
                ],
                ANSI_MARKUP.parse(
                    textwrap.dedent(
                        """\
                        ╔═══════════════════════════╗
                        ║ <header>      Query 1 of 1       </header> ║
                        ╚═══════════════════════════╝
                        Query: <ip_address>

                        <header>Actors</header>:
                        - <key><actor>     </key> <value>1</value>
                        - <key><long_actor></key> <value>1</value>

                        <header>ASNs</header>:
                        - <key><asn>     </key> <value>1</value>
                        - <key><long_asn></key> <value>1</value>

                        <header>Categories</header>:
                        - <key><category>     </key> <value>1</value>
                        - <key><long_category></key> <value>1</value>

                        <header>Classifications</header>:
                        - <key><classification>     </key> <value>1</value>
                        - <key><long_classification></key> <value>1</value>

                        <header>Source Countries</header>:
                        - <key><country>     </key> <value>1</value>
                        - <key><long_country></key> <value>1</value>

                        <header>Destination Countries</header>:
                        - <key><country>     </key> <value>1</value>
                        - <key><long_country></key> <value>1</value>

                        <header>Operating systems</header>:
                        - <key><operating_system>     </key> <value>1</value>
                        - <key><long_operating_system></key> <value>1</value>

                        <header>Organizations</header>:
                        - <key><organization>     </key> <value>1</value>
                        - <key><long_organization></key> <value>1</value>

                        <header>Spoofable</header>:
                        - <key><spoofable></key> <value>     1</value>
                        - <key><spoofable></key> <value>     1</value>

                        <header>Tags</header>:
                        - <key><tag>     </key> <value>1</value>
                        - <key><long_tag></key> <value>1</value>"""
                    )
                ),
            ),
        ),
    )
    def test_format_gnql_stats(self, result, expected):
        """Format GNQL stats."""
        assert gnql_stats_formatter(result, verbose=False).strip("\n") == expected


class TestRIOTFormatter:
    """Test RIOT formatter."""

    @pytest.mark.parametrize(
        "result, expected_output",
        (
            (
                {
                    "ip": "0.0.0.0",
                    "business_service_intelligence": {
                        "found": True,
                        "name": "<name>",
                        "category": "<category>",
                        "trust_level": "<trust_level>",
                        "last_updated": "<last_updated>",
                    },
                    "internet_scanner_intelligence": {
                        "actor": "",
                        "bot": False,
                        "classification": "",
                    },
                },
                ANSI_MARKUP.parse(
                    "<riot>0.0.0.0</riot> is in <bold><blue>RIOT</blue></bold>"
                    " dataset. Name: <green><name></green> "
                    "Category: <green><category></green> "
                    "Trust Level: <green><trust_level></green> "
                    "Last Updated: <green><last_updated></green>"
                ),
            ),
            (
                {
                    "ip": "0.0.0.0",
                    "business_service_intelligence": {"found": False},
                    "internet_scanner_intelligence": {
                        "actor": "",
                        "bot": False,
                        "classification": "",
                    },
                },
                ANSI_MARKUP.parse(
                    "<not-riot>0.0.0.0</not-riot> is <red>"
                    "<bold>NOT FOUND</bold></red> in RIOT dataset."
                ),
            ),
        ),
    )
    def test_format_riot(self, result, expected_output):
        """Test RIOT formatter."""
        formatter = riot_formatter([result], verbose=False)
        assert formatter.strip("\n") == expected_output

    @pytest.mark.parametrize(
        "result, expected_output",
        (
            (
                [
                    {
                        "business_service_intelligence": {
                            "found": True,
                            "category": "<category>",
                            "name": "<name>",
                            "description": "<description>",
                            "explanation": "<explanation>",
                            "last_updated": "<last_updated>",
                            "reference": "<reference>",
                            "trust_level": "<trust_level>",
                        },
                        "internet_scanner_intelligence": {
                            "actor": "",
                            "bot": False,
                            "classification": "",
                        },
                        "ip": "0.0.0.0",
                        "request_metadata": {"restricted_fields": []},
                    }
                ],
                ANSI_MARKUP.parse(
                    textwrap.dedent(
                        """\
                    <riot>0.0.0.0</riot> is in RIOT dataset.

                              <header>OVERVIEW</header>
                    ----------------------------
                    <key>IP</key>: <value>0.0.0.0</value>
                    <key>RIOT</key>: <value>True</value>
                    <key>Category</key>: <value><category></value>
                    <key>Trust Level</key>: <value><trust_level></value>
                    <key>Name</key>: <value><name></value>
                    <key>Description</key>: <value><description></value>
                    <key>Explanation</key>: <value><explanation></value>
                    <key>Last Updated</key>: <value><last_updated></value>
                    <key>Reference</key>: <value><reference></value>"""
                    )
                ),
            ),
        ),
    )
    def test_format_riot_verbose(self, result, expected_output):
        """Format IP quick check."""
        formatter = riot_formatter(result, verbose=True)
        assert formatter.strip("\n") == expected_output
