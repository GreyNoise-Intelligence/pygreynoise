"""GreyNoise API client."""

import functools
import re
from collections import OrderedDict

import cachetools
import more_itertools
import requests
import structlog

from greynoise.__version__ import __version__
from greynoise.exceptions import RateLimitError, RequestFailure
from greynoise.util import configure_logging, load_config, validate_ip

if not structlog.is_configured():
    configure_logging()
LOGGER = structlog.get_logger()


class GreyNoise(object):

    """GreyNoise API client.

    :param api_key: Key use to access the API.
    :type api_key: str
    :param timeout: API requests timeout in seconds.
    :type timeout: int

    """

    NAME = "GreyNoise"
    BASE_URL = "https://enterprise.api.greynoise.io"
    API_VERSION = "v2"
    EP_GNQL = "experimental/gnql"
    EP_GNQL_STATS = "experimental/gnql/stats"
    EP_INTERESTING = "interesting/{ip_address}"
    EP_NOISE_MULTI = "noise/multi/quick"
    EP_NOISE_CONTEXT = "noise/context/{ip_address}"
    EP_NOT_IMPLEMENTED = "request/{subcommand}"
    UNKNOWN_CODE_MESSAGE = "Code message unknown: {}"
    CODE_MESSAGES = {
        "0x00": "IP has never been observed scanning the Internet",
        "0x01": "IP has been observed by the GreyNoise sensor network",
        "0x02": (
            "IP has been observed scanning the GreyNoise sensor network, "
            "but has not completed a full connection, meaning this can be spoofed"
        ),
        "0x03": (
            "IP is adjacent to another host that has been directly observed "
            "by the GreyNoise sensor network"
        ),
        "0x04": "RESERVED",
        "0x05": "IP is commonly spoofed in Internet-scan activity",
        "0x06": (
            "IP has been observed as noise, but this host belongs to a cloud provider "
            "where IPs can be cycled frequently"
        ),
        "0x07": "IP is invalid",
        "0x08": (
            "IP was classified as noise, but has not been observed "
            "engaging in Internet-wide scans or attacks in over 60 days"
        ),
    }

    CACHE_MAX_SIZE = 1000
    CACHE_TTL = 3600
    IP_QUICK_CHECK_CACHE = cachetools.TTLCache(maxsize=CACHE_MAX_SIZE, ttl=CACHE_TTL)
    IP_CONTEXT_CACHE = cachetools.TTLCache(maxsize=CACHE_MAX_SIZE, ttl=CACHE_TTL)

    IP_QUICK_CHECK_CHUNK_SIZE = 1000

    IPV4_REGEX = re.compile(
        r"(?:{octet}\.){{3}}{octet}".format(
            octet=r"(?:(?:25[0-5])|(?:2[0-4]\d)|(?:1?\d?\d))"
        )
    )
    ANALYZE_TEXT_CHUNK_SIZE = 10000
    FILTER_TEXT_CHUNK_SIZE = 10000

    SECTION_KEY_TO_ELEMENT_KEY = {
        "actors": "actor",
        "asns": "asn",
        "categories": "category",
        "classifications": "classification",
        "countries": "country",
        "operating_systems": "operating_system",
        "organizations": "organization",
        "tags": "tag",
    }

    def __init__(self, api_key=None, timeout=None, use_cache=True):
        if api_key is None or timeout is None:
            config = load_config()
            if api_key is None:
                api_key = config["api_key"]
            if timeout is None:
                timeout = config["timeout"]
        self.api_key = api_key
        self.timeout = timeout
        self.use_cache = use_cache
        self.session = requests.Session()

    def _request(self, endpoint, params=None, json=None, method="get"):
        """Handle the requesting of information from the API.

        :param endpoint: Endpoint to send the request to
        :type endpoint: str
        :param params: Request parameters
        :type param: dict
        :param json: Request's JSON payload
        :type json: dict
        :param method: Request method name
        :type method: str
        :returns: Response's JSON payload
        :rtype: dict
        :raises RequestFailure: when HTTP status code is not 2xx

        """
        if params is None:
            params = {}
        headers = {
            "User-Agent": "GreyNoise/{}".format(__version__),
            "key": self.api_key,
        }
        url = "/".join([self.BASE_URL, self.API_VERSION, endpoint])
        LOGGER.debug(
            "Sending API request...", url=url, method=method, params=params, json=json
        )
        request_method = getattr(self.session, method)
        response = request_method(
            url, headers=headers, timeout=self.timeout, params=params, json=json
        )
        content_type = response.headers.get("Content-Type", "")
        if "application/json" in content_type:
            body = response.json()
        else:
            body = response.text

        LOGGER.debug(
            "API response received",
            status_code=response.status_code,
            content_type=content_type,
            body=body,
        )

        if response.status_code == 429:
            raise RateLimitError()
        if response.status_code >= 400:
            raise RequestFailure(response.status_code, body)

        return body

    def analyze(self, text):
        """Aggregate stats related to IP addresses from a given text.

        :param text: Text input
        :type text: file-like | str
        :return: Aggregated stats for all the IP addresses found.
        :rtype: dict

        """
        if isinstance(text, str):
            text = text.splitlines()
        chunks = more_itertools.chunked(text, self.ANALYZE_TEXT_CHUNK_SIZE)
        text_stats = {
            "query": [],
            "count": 0,
            "stats": {},
        }
        text_ip_addresses = set()
        chunks_stats = [
            self._analyze_chunk(chunk, text_ip_addresses) for chunk in chunks
        ]
        functools.reduce(self._aggregate_stats, chunks_stats, text_stats)

        # This maps section dictionaries to list of dictionaries
        # (undoing mapping done previously to keep track of count values)
        for section_key, section_value in text_stats["stats"].items():
            section_element_key = self.SECTION_KEY_TO_ELEMENT_KEY[section_key]
            text_stats["stats"][section_key] = sorted(
                [
                    {section_element_key: element_key, "count": element_count}
                    for element_key, element_count in section_value.items()
                ],
                key=lambda element: (-element["count"], element[section_element_key]),
            )

        return text_stats

    def _analyze_chunk(self, text, text_ip_addresses):
        """Analyze chunk of lines that contain IP addresses from a given text.

        :param text: Text input
        :type text: str
        :param text_ip_addresses: IP addresses already seen in other chunks.
        :type text_ip_addresses: set(str)
        :return: Iterator with stats for each one of the IP addresses found.
        :rtype: dict

        """
        chunk_ip_addresses = set()
        for input_line in text:
            chunk_ip_addresses.update(self.IPV4_REGEX.findall(input_line))

        # Keep only IP addresses not seen in other chunks and query those
        chunk_ip_addresses -= text_ip_addresses
        text_ip_addresses.update(chunk_ip_addresses)

        chunk_stats = [
            self.stats(query=ip_address) for ip_address in chunk_ip_addresses
        ]
        return chunk_stats

    def _aggregate_stats(self, accumulator, chunk_stats):
        """Aggregate stats for different IP addresses.

        :param accumulator: Aggregated stats for multiple IP addresses.
        :type accumulator: dict
        :param chunk_stats:
            Stats for given chunk of text. These stats are not aggregated yet,
            so they are a list of stats for each query made for that chunk.
        :type chunk_stats: list(dict)

        """
        for query_stats in chunk_stats:
            accumulator["query"].append(query_stats["query"])
            accumulator["count"] += query_stats["count"]
            for section_key, section_values in query_stats["stats"].items():
                if section_values is None:
                    continue
                section_stats = accumulator["stats"].setdefault(section_key, {})

                # This maps a list of dictionaries to a dictionary
                # to easily keep track of counts.
                section_element_key = self.SECTION_KEY_TO_ELEMENT_KEY[section_key]
                for section_value in section_values:
                    element_key = section_value[section_element_key]
                    element_count = section_value["count"]
                    section_stats.setdefault(element_key, 0)
                    section_stats[element_key] += element_count

        return accumulator

    def filter(self, text, noise_only=False):
        """Filter lines that contain IP addresses from a given text.

        :param text: Text input
        :type text: file-like | str
        :param noise_only:
            If set, return only lines that contain IP addresses classified as noise,
            otherwise, return lines that contain IP addresses not classified as noise.
        :type noise_only: bool
        :return: Iterator that yields lines in chunks
        :rtype: iterable

        """
        if isinstance(text, str):
            text = text.splitlines()
        chunks = more_itertools.chunked(text, self.FILTER_TEXT_CHUNK_SIZE)
        for chunk in chunks:
            yield self._filter_chunk(chunk, noise_only)

    def _filter_chunk(self, text, noise_only):
        """Filter chunk of lines that contain IP addresses from a given text.

        :param text: Text input
        :type text: str
        :param noise_only:
            If set, return only lines that contain IP addresses classified as noise,
            otherwise, return lines that contain IP addresses not classified as noise.
        :type noise_only: bool
        :return: Filtered line

        """
        text_ip_addresses = set()
        for input_line in text:
            text_ip_addresses.update(self.IPV4_REGEX.findall(input_line))

        noise_ip_addresses = {
            result["ip"] for result in self.quick(text_ip_addresses) if result["noise"]
        }

        def all_ip_addresses_noisy(line):
            """Select lines that contain IP addresses and all of them are noisy.

            :param line: Line being processed.
            :type line: str
            :return: True if line contains IP addresses and all of them are noisy.
            :rtype: bool

            """
            line_ip_addresses = self.IPV4_REGEX.findall(line)
            return line_ip_addresses and all(
                line_ip_address in noise_ip_addresses
                for line_ip_address in line_ip_addresses
            )

        def add_markup(match):
            """Add markup to surround IP address value with proper tag.

            :param match: IP address match
            :type match: re.Match
            :return: IP address with markup
            :rtype: str

            """
            ip_address = match.group(0)
            if ip_address in noise_ip_addresses:
                tag = "noise"
            else:
                tag = "not-noise"

            return "<{tag}>{ip_address}</{tag}>".format(ip_address=ip_address, tag=tag)

        if noise_only:
            line_matches = all_ip_addresses_noisy
        else:

            def line_matches(line):
                """Match all lines that contain either text or non-noisy lines.

                :param line: Line being processed.
                :type line: str
                :return: True if line matches as expected.
                :rtype: bool

                """
                return not all_ip_addresses_noisy(line)

        filtered_lines = [
            self.IPV4_REGEX.subn(add_markup, input_line)[0]
            for input_line in text
            if line_matches(input_line)
        ]
        return "".join(filtered_lines)

    def interesting(self, ip_address):
        """Report an IP as "interesting".

        :param ip_address: IP address to report as "interesting".
        :type ip_address: str

        """
        LOGGER.debug(
            "Reporting interesting IP: %s...", ip_address, ip_address=ip_address
        )
        validate_ip(ip_address)

        endpoint = self.EP_INTERESTING.format(ip_address=ip_address)
        response = self._request(endpoint, method="post")
        return response

    def ip(self, ip_address):
        """Get context associated with an IP address.

        :param ip_address: IP address to use in the look-up.
        :type ip_address: str
        :return: Context for the IP address.
        :rtype: dict

        """
        LOGGER.debug("Getting context for %s...", ip_address, ip_address=ip_address)
        validate_ip(ip_address)

        endpoint = self.EP_NOISE_CONTEXT.format(ip_address=ip_address)
        if self.use_cache:
            cache = self.IP_CONTEXT_CACHE
            response = (
                cache[ip_address]
                if ip_address in self.IP_CONTEXT_CACHE
                else cache.setdefault(ip_address, self._request(endpoint))
            )
        else:
            response = self._request(endpoint)

        if "ip" not in response:
            response["ip"] = ip_address

        return response

    def not_implemented(self, subcommand_name):
        """Send request for a not implemented CLI subcommand.

        :param subcommand_name: Name of the CLI subcommand
        :type subcommand_name: str

        """
        endpoint = self.EP_NOT_IMPLEMENTED.format(subcommand=subcommand_name)
        response = self._request(endpoint)
        return response

    def query(self, query, size=None, scroll=None):
        """Run GNQL query."""
        LOGGER.debug(
            "Running GNQL query: %s...", query, query=query, size=size, scroll=scroll
        )
        params = {"query": query}
        if size is not None:
            params["size"] = size
        if scroll is not None:
            params["scroll"] = scroll
        response = self._request(self.EP_GNQL, params=params)
        return response

    def quick(self, ip_addresses):
        """Get activity associated with one or more IP addresses.

        :param ip_addresses: One or more IP addresses to use in the look-up.
        :type ip_addresses: str | list
        :return: Bulk status information for IP addresses.
        :rtype: dict

        """
        if isinstance(ip_addresses, str):
            ip_addresses = [ip_addresses]

        LOGGER.debug(
            "Getting noise status for %s...", ip_addresses, ip_addresses=ip_addresses
        )
        ip_addresses = [
            ip_address
            for ip_address in ip_addresses
            if validate_ip(ip_address, strict=False)
        ]

        if self.use_cache:
            cache = self.IP_QUICK_CHECK_CACHE
            # Keep the same ordering as in the input
            ordered_results = OrderedDict(
                (ip_address, cache.get(ip_address)) for ip_address in ip_addresses
            )
            api_ip_addresses = [
                ip_address
                for ip_address, result in ordered_results.items()
                if result is None
            ]
            if api_ip_addresses:
                api_results = []
                chunks = more_itertools.chunked(
                    api_ip_addresses, self.IP_QUICK_CHECK_CHUNK_SIZE
                )
                for chunk in chunks:
                    api_result = self._request(self.EP_NOISE_MULTI, json={"ips": chunk})
                    if isinstance(api_result, list):
                        api_results.extend(api_result)
                    else:
                        api_results.append(api_result)

                for api_result in api_results:
                    ip_address = api_result["ip"]
                    ordered_results[ip_address] = cache.setdefault(
                        ip_address, api_result
                    )
            results = list(ordered_results.values())
        else:
            results = []
            chunks = more_itertools.chunked(
                ip_addresses, self.IP_QUICK_CHECK_CHUNK_SIZE
            )
            for chunk in chunks:
                result = self._request(self.EP_NOISE_MULTI, json={"ips": chunk})
                if isinstance(result, list):
                    results.extend(result)
                else:
                    results.append(result)

        for result in results:
            code = result["code"]
            result["code_message"] = self.CODE_MESSAGES.get(
                code, self.UNKNOWN_CODE_MESSAGE.format(code)
            )
        return results

    def stats(self, query):
        """Run GNQL stats query."""
        LOGGER.debug("Running GNQL stats query: %s...", query, query=query)
        response = self._request(self.EP_GNQL_STATS, params={"query": query})
        return response
