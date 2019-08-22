"""GreyNoise API client."""

import logging

import requests

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
    CLIENT_VERSION = "0.2.0"
    API_VERSION = "v2"
    EP_GNQL = "experimental/gnql"
    EP_GNQL_STATS = "experimental/gnql/stats"
    EP_NOISE_QUICK = "noise/quick/{ip_address}"
    EP_NOISE_MULTI = "noise/multi/quick"
    EP_NOISE_CONTEXT = "noise/context/{ip_address}"
    EP_RESEARCH_ACTORS = "research/actors"
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

    def __init__(self, api_key=None, timeout=7):
        if api_key is None:
            api_key = load_config()["api_key"]
        self.api_key = api_key
        self.timeout = timeout
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
            "User-Agent": "greyNoise/{}".format(self.CLIENT_VERSION),
            "key": self.api_key,
        }
        url = "/".join([self.BASE_URL, self.API_VERSION, endpoint])
        response = self.session.get(
            url, headers=headers, timeout=self.timeout, params=params, json=json
        )

        if response.status_code == 429:
            raise RateLimitError()
        if not 200 <= response.status_code < 300:
            raise RequestFailure(response.status_code, response.content)

        body = response.json()
        if "error" in body:
            raise RequestFailure(response.status_code, body)

        return body

    def get_noise_status(self, ip_address):
        """Get activity associated with an IP address.

        :param ip_address: IP address to use in the look-up.
        :type recurse: str
        :return: Activity metadata for the IP address.
        :rtype: dict

        """
        LOGGER.debug("Getting noise status for %s...", ip_address)
        validate_ip(ip_address)
        endpoint = self.EP_NOISE_QUICK.format(ip_address=ip_address)
        result = self._request(endpoint)
        code = result["code"]
        result["code_message"] = self.CODE_MESSAGES.get(
            code, self.UNKNOWN_CODE_MESSAGE.format(code)
        )
        return result

    def get_noise_status_bulk(self, ip_addresses):
        """Get activity associated with multiple IP addresses.

        :param ip_addresses: IP addresses to use in the look-up.
        :type ip_addresses: list
        :return: Bulk status information for IP addresses.
        :rtype: dict

        """
        LOGGER.debug("Getting noise status for %s...", ip_addresses)
        if not isinstance(ip_addresses, list):
            raise ValueError("`ip_addresses` must be a list")

        ip_addresses = [
            ip_address
            for ip_address in ip_addresses
            if validate_ip(ip_address, strict=False)
        ]
        results = self._request(self.EP_NOISE_MULTI, json={"ips": ip_addresses})
        if isinstance(results, list):
            for result in results:
                code = result["code"]
                result["code_message"] = self.CODE_MESSAGES.get(
                    code, self.UNKNOWN_CODE_MESSAGE.format(code)
                )
        return results

    def get_context(self, ip_address):
        """Get context associated with an IP address.

        :param ip_address: IP address to use in the look-up.
        :type recurse: str
        :return: Context for the IP address.
        :rtype: dict

        """
        LOGGER.debug("Getting context for %s...", ip_address)
        validate_ip(ip_address)
        endpoint = self.EP_NOISE_CONTEXT.format(ip_address=ip_address)
        response = self._request(endpoint)
        return response

    def get_actors(self):
        """Get the names and IP addresses of actors scanning the Internet.

        :returns: Most labeled actors scanning the intenet.
        :rtype: list

        """
        LOGGER.debug("Getting actors...")
        response = self._request(self.EP_RESEARCH_ACTORS)
        return response

    def run_query(self, query):
        """Run GNQL query."""
        LOGGER.debug("Running GNQL query: %s...", query)
        response = self._request(self.EP_GNQL, params={"query": query})
        return response

    def run_stats_query(self, query):
        """Run GNQL stats query."""
        LOGGER.debug("Running GNQL stats query: %s...", query)
        response = self._request(self.EP_GNQL_STATS, params={"query": query})
        return response
