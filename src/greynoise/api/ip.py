import logging

import cachetools

from greynoise.api.base import MAX_SIZE, TTL, Base
from greynoise.util import validate_ip

LOGGER = logging.getLogger(__name__)


class IP(Base):

    EP_NOISE_CONTEXT = "noise/context/{ip_address}"
    IP_CONTEXT_CACHE = cachetools.TTLCache(maxsize=MAX_SIZE, ttl=TTL)

    def __call__(self, ip_address):
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
