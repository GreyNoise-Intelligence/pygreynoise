import logging
from collections import OrderedDict

import cachetools

from greynoise.api.base import Base
from greynoise.util import validate_ip

LOGGER = logging.getLogger(__name__)


class IP(Base):

    EP_NOISE_QUICK = "noise/quick/{ip_address}"
    EP_NOISE_MULTI = "noise/multi/quick"
    EP_NOISE_CONTEXT = "noise/context/{ip_address}"
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

    MAX_SIZE = 1000
    TTL = 3600
    IP_QUICK_CHECK_CACHE = cachetools.TTLCache(maxsize=MAX_SIZE, ttl=TTL)
    IP_CONTEXT_CACHE = cachetools.TTLCache(maxsize=MAX_SIZE, ttl=TTL)

    def quick_check(self, ip_address):
        """Get activity associated with an IP address.

        :param ip_address: IP address to use in the look-up.
        :type recurse: str
        :return: Activity metadata for the IP address.
        :rtype: dict

        """
        LOGGER.debug("Getting noise status for %s...", ip_address)
        validate_ip(ip_address)

        endpoint = self.EP_NOISE_QUICK.format(ip_address=ip_address)
        if self.use_cache:
            cache = self.IP_QUICK_CHECK_CACHE
            response = (
                cache[ip_address]
                if ip_address in cache
                else cache.setdefault(ip_address, self._request(endpoint))
            )
        else:
            response = self._request(endpoint)

        code = response["code"]
        response["code_message"] = self.CODE_MESSAGES.get(
            code, self.UNKNOWN_CODE_MESSAGE.format(code)
        )
        return response

    def multi_quick_check(self, ip_addresses):
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

        if self.use_cache:
            cache = self.IP_QUICK_CHECK_CACHE
            # Keep the same ordering as in the input
            results = OrderedDict(
                (ip_address, cache.get(ip_address)) for ip_address in ip_addresses
            )
            api_ip_addresses = [
                ip_address for ip_address, result in results.items() if result is None
            ]
            if api_ip_addresses:
                api_results = self._request(
                    self.EP_NOISE_MULTI, json={"ips": api_ip_addresses}
                )
                for api_result in api_results:
                    ip_address = api_result["ip"]
                    results[ip_address] = cache.setdefault(ip_address, api_result)
            results = list(results.values())
        else:
            results = self._request(self.EP_NOISE_MULTI, json={"ips": ip_addresses})

        for result in results:
            code = result["code"]
            result["code_message"] = self.CODE_MESSAGES.get(
                code, self.UNKNOWN_CODE_MESSAGE.format(code)
            )
        return results

    def context(self, ip_address):
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
