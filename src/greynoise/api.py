"""GreyNoise API client."""

import logging
from collections import OrderedDict

import cachetools
import more_itertools
import requests

from greynoise.__version__ import __version__
from greynoise.exceptions import RateLimitError, RequestFailure
from greynoise.util import load_config, validate_ip

LOGGER = logging.getLogger(__name__)


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
    EP_NOISE_QUICK = "noise/quick/{ip_address}"
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

    def _request(self, endpoint, params=None, json=None):
        """Handle the requesting of information from the API.

        :param endpoint: Endpoint to send the request to.
        :type endpoint: str
        :param params: Request parameters.
        :type param: dict
        :param json: Request's JSON payload.
        :type json: dict
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
        response = self.session.get(
            url, headers=headers, timeout=self.timeout, params=params, json=json
        )

        if "application/json" in response.headers.get("Content-Type", ""):
            body = response.json()
        else:
            body = response.text

        if response.status_code == 429:
            raise RateLimitError()
        if response.status_code >= 400:
            raise RequestFailure(response.status_code, body)

        return body

    def ip(self, ip_address):
        """Get context associated with an IP address.

        :param ip_address: IP address to use in the look-up.
        :type recurse: str
        :return: Context for the IP address.
        :rtype: dict

        """
        LOGGER.debug("Getting context for %s...", ip_address)
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

    def query(self, query):
        """Run GNQL query."""
        LOGGER.debug("Running GNQL query: %s...", query)
        response = self._request(self.EP_GNQL, params={"query": query})
        return response

    def quick(self, ip_addresses):
        """Get activity associated with one or more IP addresses.

        :param ip_addresses: One or more IP addresses to use in the look-up.
        :type ip_addresses: str | list
        :return: Bulk status information for IP addresses.
        :rtype: dict

        """
        LOGGER.debug("Getting noise status for %s...", ip_addresses)
        if isinstance(ip_addresses, str):
            ip_addresses = [ip_addresses]

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
                if len(api_ip_addresses) == 1:
                    endpoint = self.EP_NOISE_QUICK.format(
                        ip_address=api_ip_addresses[0]
                    )
                    api_results.append(self._request(endpoint))
                else:
                    chunks = more_itertools.chunked(
                        api_ip_addresses, self.IP_QUICK_CHECK_CHUNK_SIZE
                    )
                    for chunk in chunks:
                        api_results.extend(
                            self._request(self.EP_NOISE_MULTI, json={"ips": chunk})
                        )

                for api_result in api_results:
                    ip_address = api_result["ip"]
                    ordered_results[ip_address] = cache.setdefault(
                        ip_address, api_result
                    )
            results = list(ordered_results.values())
        else:
            results = []
            if len(ip_addresses) == 1:
                endpoint = self.EP_NOISE_QUICK.format(ip_address=ip_addresses[0])
                results.append(self._request(endpoint))
            else:
                chunks = more_itertools.chunked(
                    ip_addresses, self.IP_QUICK_CHECK_CHUNK_SIZE
                )
                for chunk in chunks:
                    results.extend(
                        self._request(self.EP_NOISE_MULTI, json={"ips": chunk})
                    )

        for result in results:
            code = result["code"]
            result["code_message"] = self.CODE_MESSAGES.get(
                code, self.UNKNOWN_CODE_MESSAGE.format(code)
            )
        return results

    def stats(self, query):
        """Run GNQL stats query."""
        LOGGER.debug("Running GNQL stats query: %s...", query)
        response = self._request(self.EP_GNQL_STATS, params={"query": query})
        return response
