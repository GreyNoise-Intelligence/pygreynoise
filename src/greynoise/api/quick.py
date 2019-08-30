import logging
from collections import OrderedDict

import cachetools

from greynoise.api.base import MAX_SIZE, TTL, Base
from greynoise.util import validate_ip

LOGGER = logging.getLogger(__name__)


class Quick(Base):

    EP_NOISE_QUICK = "noise/quick/{ip_address}"
    EP_NOISE_MULTI = "noise/multi/quick"
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

    IP_QUICK_CHECK_CACHE = cachetools.TTLCache(maxsize=MAX_SIZE, ttl=TTL)

    def __call__(self, ip_addresses):
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
                if len(api_ip_addresses) == 1:
                    endpoint = self.EP_NOISE_QUICK.format(
                        ip_address=api_ip_addresses[0]
                    )
                    api_results = [self._request(endpoint)]
                else:
                    api_results = self._request(
                        self.EP_NOISE_MULTI, json={"ips": api_ip_addresses}
                    )

                for api_result in api_results:
                    ip_address = api_result["ip"]
                    results[ip_address] = cache.setdefault(ip_address, api_result)
            results = list(results.values())
        else:
            if len(ip_addresses) == 1:
                endpoint = self.EP_NOISE_QUICK.format(ip_address=api_ip_addresses[0])
                api_results = [self._request(endpoint)]
            else:
                results = self._request(self.EP_NOISE_MULTI, json={"ips": ip_addresses})

        for result in results:
            code = result["code"]
            result["code_message"] = self.CODE_MESSAGES.get(
                code, self.UNKNOWN_CODE_MESSAGE.format(code)
            )
        return results
