"""GreyNoise API client."""

import re
from collections import OrderedDict

import cachetools
import more_itertools
import requests
import structlog

from greynoise.__version__ import __version__
from greynoise.api.analyzer import Analyzer
from greynoise.api.filter import Filter
from greynoise.exceptions import RateLimitError, RequestFailure
from greynoise.util import configure_logging, load_config, validate_ip

if not structlog.is_configured():
    configure_logging()
LOGGER = structlog.get_logger()


def initialize_cache(cache_max_size, cache_ttl):
    """A function to initialize cache"""
    cache = cachetools.TTLCache(maxsize=cache_max_size, ttl=cache_ttl)
    return cache


class GreyNoise(object):

    """GreyNoise API client.

    :param api_key: Key use to access the API.
    :type api_key: str
    :param timeout: API requests timeout in seconds.
    :type timeout: int
    :param proxy: Add URL for proxy to redirect lookups
    :type proxy: str

    """

    NAME = "GreyNoise"
    API_VERSION = "v2"
    EP_GNQL = "experimental/gnql"
    EP_GNQL_STATS = "experimental/gnql/stats"
    EP_INTERESTING = "interesting/{ip_address}"
    EP_NOISE_MULTI = "noise/multi/quick"
    EP_NOISE_CONTEXT = "noise/context/{ip_address}"
    EP_COMMUNITY_IP = "v3/community/{ip_address}"
    EP_META_METADATA = "meta/metadata"
    EP_PING = "ping"
    EP_RIOT = "riot/{ip_address}"
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
        "404": "IP is Invalid",
    }

    IP_QUICK_CHECK_CHUNK_SIZE = 1000

    IPV4_REGEX = re.compile(
        r"(?:{octet}\.){{3}}{octet}".format(
            octet=r"(?:(?:25[0-5])|(?:2[0-4]\d)|(?:1?\d?\d))"
        )
    )

    def __init__(
        self,
        api_key=None,
        api_server=None,
        timeout=None,
        proxy=None,
        use_cache=True,
        integration_name=None,
        cache_max_size=None,
        cache_ttl=None,
        offering=None,
    ):
        if any(
            configuration_value is None
            for configuration_value in (api_key, timeout, api_server, proxy, offering)
        ):
            config = load_config()
            if api_key is None:
                api_key = config["api_key"]
            if api_server is None:
                api_server = config["api_server"]
            if timeout is None:
                timeout = config["timeout"]
            if proxy is None:
                proxy = config["proxy"]
            if offering is None:
                offering = config["offering"]
        self.api_key = api_key
        self.api_server = api_server
        self.timeout = timeout
        self.proxy = proxy
        self.use_cache = use_cache
        self.integration_name = integration_name
        self.session = requests.Session()
        self.offering = offering

        if cache_ttl is None or not isinstance(cache_ttl, int):
            cache_ttl = 3600
        self.cache_ttl = cache_ttl

        if cache_max_size is None or not isinstance(cache_max_size, int):
            cache_max_size = 1000
        self.cache_max_size = cache_max_size

        if use_cache:
            self.ip_quick_check_cache = initialize_cache(cache_max_size, cache_ttl)
            self.ip_context_cache = initialize_cache(cache_max_size, cache_ttl)

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

        user_agent_parts = ["GreyNoise/{}".format(__version__)]
        if self.integration_name:
            user_agent_parts.append("({})".format(self.integration_name))
        headers = {
            "User-Agent": " ".join(user_agent_parts),
            "key": self.api_key,
        }
        if self.offering.lower() == "community":
            url = "/".join([self.api_server, endpoint])
        elif endpoint == self.EP_PING:
            url = "/".join([self.api_server, endpoint])
        else:
            url = "/".join([self.api_server, self.API_VERSION, endpoint])

        LOGGER.debug(
            "Sending API request...",
            url=url,
            method=method,
            headers=headers,
            params=params,
            json=json,
            proxy=self.proxy,
        )
        request_method = getattr(self.session, method)
        if self.proxy:
            proxies = {protocol: self.proxy for protocol in ("http", "https")}
            response = request_method(
                url,
                headers=headers,
                timeout=self.timeout,
                params=params,
                json=json,
                proxies=proxies,
            )
        else:
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
        if response.status_code >= 400 and response.status_code != 404:
            raise RequestFailure(response.status_code, body)

        return body

    def analyze(self, text):
        """Aggregate stats related to IP addresses from a given text.

        :param text: Text input
        :type text: file-like | str
        :return: Aggregated stats for all the IP addresses found.
        :rtype: dict

        """
        if self.offering == "community":
            response = [
                {"message": "Quick Lookup not supported with Community offering"}
            ]
            return response
        else:
            analyzer = Analyzer(self)
            return analyzer.analyze(text)

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
        filter = Filter(self)
        for filtered_chunk in filter.filter(text, noise_only=noise_only):
            yield filtered_chunk

    def interesting(self, ip_address):
        """Report an IP as "interesting".

        :param ip_address: IP address to report as "interesting".
        :type ip_address: str

        """
        if self.offering == "community":
            response = {
                "message": "Interesting report not supported with Community offering"
            }
            return response
        else:
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

        if self.offering.lower() == "community":
            endpoint = self.EP_COMMUNITY_IP.format(ip_address=ip_address)
        else:
            endpoint = self.EP_NOISE_CONTEXT.format(ip_address=ip_address)
        if self.use_cache:
            cache = self.ip_context_cache
            response = (
                cache[ip_address]
                if ip_address in self.ip_context_cache
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
        if self.offering == "community":
            response = {"message": "GNQL not supported with Community offering"}
            return response
        else:
            LOGGER.debug(
                "Running GNQL query: %s...",
                query,
                query=query,
                size=size,
                scroll=scroll,
            )
            params = {"query": query}
            if size is not None:
                params["size"] = size
            if scroll is not None:
                params["scroll"] = scroll
            response = self._request(self.EP_GNQL, params=params)
            return response

    def quick(self, ip_addresses, include_invalid=False):  # noqa: C901
        """Get activity associated with one or more IP addresses.

        :param ip_addresses: One or more IP addresses to use in the look-up.
        :type ip_addresses: str | list
        :return: Bulk status information for IP addresses.
        :rtype: dict

        :param include_invalid: True or False
        :type include_invalid: bool

        """
        if self.offering == "community":
            response = [
                {"message": "Quick Lookup not supported with Community offering"}
            ]
            return response
        else:
            if isinstance(ip_addresses, str):
                ip_addresses = ip_addresses.split(",")

            LOGGER.debug("Getting noise status...", ip_addresses=ip_addresses)

            valid_ip_addresses = [
                ip_address
                for ip_address in ip_addresses
                if validate_ip(ip_address, strict=False)
            ]

            if self.use_cache:
                cache = self.ip_quick_check_cache
                # Keep the same ordering as in the input
                ordered_results = OrderedDict(
                    (ip_address, cache.get(ip_address))
                    for ip_address in valid_ip_addresses
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
                        api_result = self._request(
                            self.EP_NOISE_MULTI, json={"ips": chunk}
                        )
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
                    valid_ip_addresses, self.IP_QUICK_CHECK_CHUNK_SIZE
                )
                for chunk in chunks:
                    result = self._request(self.EP_NOISE_MULTI, json={"ips": chunk})
                    if isinstance(result, list):
                        results.extend(result)
                    else:
                        results.append(result)

            [
                results.append({"ip": ip, "noise": False, "code": "404"})
                for ip in ip_addresses
                if ip not in valid_ip_addresses and include_invalid
            ]

            for result in results:
                code = result["code"]
                result["code_message"] = self.CODE_MESSAGES.get(
                    code, self.UNKNOWN_CODE_MESSAGE.format(code)
                )
            return results

    def stats(self, query, count=None):
        """Run GNQL stats query."""
        if self.offering == "community":
            response = {"message": "Stats Query not supported with Community offering"}
            return response
        else:
            LOGGER.debug("Running GNQL stats query: %s...", query, query=query)
            params = {"query": query}
            if count is not None:
                params["count"] = count
            response = self._request(self.EP_GNQL_STATS, params=params)
            return response

    def metadata(self):
        """Get metadata."""
        if self.offering == "community":
            response = {
                "message": "Metadata lookup not supported with Community offering"
            }
            return response
        else:
            LOGGER.debug("Getting metadata...")
            response = self._request(self.EP_META_METADATA)
            return response

    def test_connection(self):
        """Test the API connection and API key."""
        LOGGER.debug("Testing access to GreyNoise API and for valid API Key")
        response = self._request(self.EP_PING)
        return response

    def riot(self, ip_address):
        """Check if IP is in RIOT data set

        :param ip_address: IP address to use in the look-up.
        :type ip_address: str
        :return: Context for the IP address.
        :rtype: dict

        """
        if self.offering == "community":
            response = {"message": "RIOT lookup not supported with Community offering"}
            return response
        else:
            LOGGER.debug("Checking RIOT for %s...", ip_address, ip_address=ip_address)
            validate_ip(ip_address)

            endpoint = self.EP_RIOT.format(ip_address=ip_address)
            response = self._request(endpoint)

            if "ip" not in response:
                response["ip"] = ip_address

            return response
