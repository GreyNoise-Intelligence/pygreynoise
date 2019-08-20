"""Formatter test cases."""

import textwrap

import pytest

from greynoise.cli.formatter import ip_context_formatter


class TestIPContextFormatter(object):
    """IP context formatter tests."""

    @pytest.mark.parametrize(
        "ip_context, expected",
        (
            (
                {
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
                            "useragents": [
                                "<useragent#1>",
                                "<useragent#2>",
                                "<useragent#3>",
                            ],
                        },
                    },
                    "seen": True,
                    "tags": ["<tag#1>", "<tag#2>", "<tag#3>"],
                },
                textwrap.dedent(
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
                ),
            ),
        ),
    )
    def test_format_ip_context(self, ip_context, expected):
        """Format IP context."""
        assert ip_context_formatter(ip_context).strip("\n") == expected
