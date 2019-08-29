import logging

from greynoise.api.base import Base

LOGGER = logging.getLogger(__name__)


class Actors(Base):

    EP_RESEARCH_ACTORS = "research/actors"

    def __call__(self):
        """Get the names and IP addresses of actors scanning the Internet.

        :returns: Most labeled actors scanning the intenet.
        :rtype: list

        """
        LOGGER.debug("Getting actors...")
        response = self._request(self.EP_RESEARCH_ACTORS)
        return response
