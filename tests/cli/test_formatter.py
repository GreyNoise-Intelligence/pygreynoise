# coding=utf-8
"""Formatter test cases."""

import textwrap

import pytest

from greynoise.cli.formatter import (
    actors_formatter,
    gnql_query_formatter,
    gnql_stats_formatter,
    ip_context_formatter,
    ip_multi_quick_check_formatter,
    ip_quick_check_formatter,
    json_formatter,
    xml_formatter,
)

EXAMPLE_IP_CONTEXT = {
    "actor": "<actor>",
    "classification": "<classification>",
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
        "rdns": "<rdns>",
        "tor": False,
    },
    "raw_data": {
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
    "tags": ["<tag#1>", "<tag#2>", "<tag#3>"],
}

EXAMPLE_IP_CONTEXT_OUTPUT = textwrap.dedent(
    """\
             OVERVIEW:
    ----------------------------
    Actor: <actor>
    Classification: <classification>
    First seen: <first_seen>
    IP: <ip_address>
    Last seen: <last_seen>
    Tags:
    - <tag#1>
    - <tag#2>
    - <tag#3>

             METADATA:
    ----------------------------
    ASN: <asn>
    Category: <category>
    Location: <city>, <country> (<country_code>)
    Organization: <organization>
    OS: <os>
    rDNS: <rdns>
    Tor: False

             RAW DATA:
    ----------------------------
    [Scan]
    - Port/Proto: 123456/TCP
    - Port/Proto: 123456/UDP

    [Paths]
    - /
    - /favicon.ico
    - /robots.txt

    [JA3]
    - Port: 123456, Fingerprint: <fingerprint#1>
    - Port: 123456, Fingerprint: <fingerprint#2>
    - Port: 123456, Fingerprint: <fingerprint#3>"""
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
            \t<a type="str">result</a>
            </root>
            """
        )


class TestIPContextFormatter(object):
    """IP context formatter tests."""

    @pytest.mark.parametrize(
        "result, expected", ((EXAMPLE_IP_CONTEXT, EXAMPLE_IP_CONTEXT_OUTPUT),)
    )
    def test_format_ip_context(self, result, expected):
        """Format IP context."""
        assert ip_context_formatter(result, verbose=False).strip("\n") == expected


class TestIPQuickCheckFormatter(object):
    """IP quick check formatter tests."""

    @pytest.mark.parametrize(
        "result, expected",
        (
            ({"ip": "0.0.0.0", "noise": True}, "0.0.0.0 is classified as NOISE."),
            ({"ip": "0.0.0.0", "noise": False}, "0.0.0.0 is classified as NOT NOISE."),
        ),
    )
    def test_format_ip_quick_check(self, result, expected):
        """Format IP quick check."""
        assert ip_quick_check_formatter(result, verbose=False) == expected


class TestIPMultiQuickCheckFormatter(object):
    """IP multi quick check formatter tests."""

    @pytest.mark.parametrize(
        "result, expected",
        (
            (
                [{"ip": "0.0.0.0", "noise": True}, {"ip": "0.0.0.1", "noise": False}],
                (
                    "\n0.0.0.0 is classified as NOISE.\n"
                    "0.0.0.1 is classified as NOT NOISE."
                ),
            ),
        ),
    )
    def test_format_multi_ip_quick_check(self, result, expected):
        """Format IP multi quick check."""
        assert ip_multi_quick_check_formatter(result, verbose=False) == expected


class TestGNQLQueryFormatter(object):
    """GNQL query formatter tests."""

    @pytest.mark.parametrize(
        "result, expected",
        (
            (
                {
                    "complete": True,
                    "count": 1,
                    "data": [EXAMPLE_IP_CONTEXT],
                    "message": "ok",
                    "query": "<ip_address>",
                },
                textwrap.dedent(
                    u"""\
                    ┌───────────────────────────┐
                    │       Result 1 of 1       │
                    └───────────────────────────┘

                    """
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
                            {"operating_system": "<long_operating_system>", "count": 1},
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
                },
                textwrap.dedent(
                    """\
                    ASNs:
                    - <asn>      1
                    - <long_asn> 1

                    Categories:
                    - <category>      1
                    - <long_category> 1

                    Classifications:
                    - <classification>      1
                    - <long_classification> 1

                    Countries:
                    - <country>      1
                    - <long_country> 1

                    Operating systems:
                    - <operating_system>      1
                    - <long_operating_system> 1

                    Organizations:
                    - <organization>      1
                    - <long_organization> 1

                    Tags:
                    - <tag>      1
                    - <long_tag> 1"""
                ),
            ),
        ),
    )
    def test_format_gnql_stats(self, result, expected):
        """Format GNQL stats."""
        assert gnql_stats_formatter(result, verbose=False).strip("\n") == expected


class TestActorsFormatter(object):
    """Actors formatter tests."""

    @pytest.mark.parametrize(
        "result, expected",
        (
            (
                [
                    {"name": "<name#1>", "ips": ["<ip#1>", "<ip#2>"]},
                    {"name": "<name#2>", "ips": ["<ip#3>", "<ip#4>"]},
                ],
                textwrap.dedent(
                    u"""\
                    ┌───────────────────────────┐
                    │       Result 1 of 2       │
                    └───────────────────────────┘

                    Name: <name#1>
                    IPs:
                    - <ip#1>
                    - <ip#2>


                    ┌───────────────────────────┐
                    │       Result 2 of 2       │
                    └───────────────────────────┘

                    Name: <name#2>
                    IPs:
                    - <ip#3>
                    - <ip#4>"""
                ),
            ),
        ),
    )
    def test_actors(self, result, expected):
        """Format actors."""
        assert actors_formatter(result, verbose=False).strip("\n") == expected
