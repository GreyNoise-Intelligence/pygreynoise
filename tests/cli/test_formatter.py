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
    "actor": "<actor>",
    "bot": False,
    "classification": "<classification>",
    "cve": ["<cve#1>", "<cve#2>"],
    "first_seen": "<first_seen>",
    "ip": "<ip_address>",
    "last_seen": "<last_seen>",
    "metadata": {
        "asn": "<asn>",
        "category": "<category>",
        "city": "<city>",
        "country": "<country>",
        "country_code": "<country_code>",
        "organization": "<organization>",
        "os": "<os>",
        "region": "<region>",
        "rdns": "<rdns>",
        "tor": False,
    },
    "raw_data": {
        "hassh": [
            {"hassh": "<hassh#1>", "port": 123456},
            {"hassh": "<hassh#2>", "port": 123456},
            {"hassh": "<hassh#3>", "port": 123456},
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
        "web": {
            "paths": ["/", "/favicon.ico", "/robots.txt"],
            "useragents": ["<useragent#1>", "<useragent#2>", "<useragent#3>"],
        },
    },
    "seen": True,
    "spoofable": False,
    "tags": ["<tag#1>", "<tag#2>", "<tag#3>"],
    "vpn": False,
    "vpn_service": "",
}

EXAMPLE_IP_CONTEXT_OUTPUT = ANSI_MARKUP.parse(
    textwrap.dedent(
        """\
                  <header>OVERVIEW</header>
        ----------------------------
        <key>Actor</key>: <value><actor></value>
        <key>Classification</key>: <value><classification></value>
        <key>First seen</key>: <value><first_seen></value>
        <key>IP</key>: <value><ip_address></value>
        <key>Last seen</key>: <value><last_seen></value>
        <key>Spoofable</key>: <value>False</value>
        <key>BOT</key>: <value>False</value>
        <key>VPN</key>: <value>False</value>
        <key>VPN Service</key>: <value></value>
        <key>Tags</key>:
        - <value><tag#1></value>
        - <value><tag#2></value>
        - <value><tag#3></value>

                  <header>METADATA</header>
        ----------------------------
        <key>ASN</key>: <value><asn></value>
        <key>Category</key>: <value><category></value>
        <key>Location</key>: <value><city>, <country> (<country_code>)</value>
        <key>Region</key>: <value><region></value>
        <key>Organization</key>: <value><organization></value>
        <key>OS</key>: <value><os></value>
        <key>rDNS</key>: <value><rdns></value>
        <key>Tor</key>: <value>False</value>

                  <header>RAW DATA</header>
        ----------------------------
        [CVE]
        - <key>CVE</key>: <value><cve#1></value>
        - <key>CVE</key>: <value><cve#2></value>

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
        - <key>Port</key>: <value>123456</value>, <key>Fingerprint</key>: <value><fingerprint#3></value>"""  # noqa
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


class TestIPContextFormatter(object):
    """IP context formatter tests."""

    @pytest.mark.parametrize(
        "result, expected",
        (
            (
                [
                    EXAMPLE_IP_CONTEXT,
                    {"error": "commonly spoofed ip", "ip": "<ip_address#2>"},
                    {"ip": "<ip_address#3>", "seen": False},
                ],
                ANSI_MARKUP.parse(
                    textwrap.dedent(
                        u"""\
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
                        u"""


                        ╔═══════════════════════════╗
                        ║ <header>     Context 2 of 3      </header> ║
                        ╚═══════════════════════════╝
                        IP address: <ip_address#2>

                        commonly spoofed ip


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


class TestIPQuickCheckFormatter(object):
    """IP quick check formatter tests."""

    @pytest.mark.parametrize(
        "result, expected",
        (
            (
                [{"ip": "0.0.0.0", "noise": True}],
                ANSI_MARKUP.parse(
                    "<noise>0.0.0.0</noise> is classified as <bold>NOISE</bold>."
                ),
            ),
            (
                [{"ip": "0.0.0.0", "noise": False}],
                ANSI_MARKUP.parse(
                    "<not-noise>0.0.0.0</not-noise> "
                    "is classified as <bold>NOT NOISE</bold>."
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
                        "complete": True,
                        "count": 1,
                        "scroll": "abcdefg",
                        "data": [EXAMPLE_IP_CONTEXT],
                        "message": "ok",
                        "query": "<ip_address>",
                    }
                ],
                ANSI_MARKUP.parse(
                    textwrap.dedent(
                        u"""\
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
        assert gnql_query_formatter(result, verbose=False).strip("\n") == expected


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
                            "actors": None,
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
                            "tags": [
                                {"tag": "<tag>", "count": 1},
                                {"tag": "<long_tag>", "count": 1},
                            ],
                        },
                    }
                ],
                ANSI_MARKUP.parse(
                    textwrap.dedent(
                        u"""\
                        ╔═══════════════════════════╗
                        ║ <header>      Query 1 of 1       </header> ║
                        ╚═══════════════════════════╝
                        Query: <ip_address>

                        <header>ASNs</header>:
                        - <key><asn>     </key> <value>1</value>
                        - <key><long_asn></key> <value>1</value>

                        <header>Categories</header>:
                        - <key><category>     </key> <value>1</value>
                        - <key><long_category></key> <value>1</value>

                        <header>Classifications</header>:
                        - <key><classification>     </key> <value>1</value>
                        - <key><long_classification></key> <value>1</value>

                        <header>Countries</header>:
                        - <key><country>     </key> <value>1</value>
                        - <key><long_country></key> <value>1</value>

                        <header>Operating systems</header>:
                        - <key><operating_system>     </key> <value>1</value>
                        - <key><long_operating_system></key> <value>1</value>

                        <header>Organizations</header>:
                        - <key><organization>     </key> <value>1</value>
                        - <key><long_organization></key> <value>1</value>

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


class TestRIOTFormatter(object):
    """RIOT formatter tests."""

    @pytest.mark.parametrize(
        "result, expected",
        (
            (
                [
                    {
                        "ip": "0.0.0.0",
                        "riot": True,
                        "category": "<category>",
                        "name": "<name>",
                        "description": "<description>",
                        "explanation": "<explanation>",
                        "last_updated": "<last_updated>",
                        "reference": "<reference>",
                        "trust_level": "<trust_level>",
                    }
                ],
                ANSI_MARKUP.parse(
                    "<riot>0.0.0.0</riot> is in RIOT dataset. "
                    "Name: <value><name></value> "
                    "Category: <value><category></value> "
                    "Trust Level: <value><trust_level></value> "
                    "Last Updated: <value><last_updated></value>"
                ),
            ),
            (
                [{"ip": "0.0.0.0", "riot": False}],
                ANSI_MARKUP.parse(
                    "<not-riot>0.0.0.0</not-riot>"
                    " is <bold>NOT FOUND</bold> in RIOT dataset."
                ),
            ),
        ),
    )
    def test_format_riot(self, result, expected):
        """Format IP quick check."""
        assert riot_formatter(result, verbose=False).strip("\n") == expected

    @pytest.mark.parametrize(
        "result, expected",
        (
            (
                [
                    {
                        "ip": "0.0.0.0",
                        "riot": True,
                        "category": "<category>",
                        "name": "<name>",
                        "description": "<description>",
                        "explanation": "<explanation>",
                        "last_updated": "<last_updated>",
                        "reference": "<reference>",
                        "trust_level": "<trust_level>",
                    }
                ],
                ANSI_MARKUP.parse(
                    textwrap.dedent(
                        u"""\
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
    def test_format_riot_verbose(self, result, expected):
        """Format IP quick check."""
        assert riot_formatter(result, verbose=True).strip("\n") == expected
