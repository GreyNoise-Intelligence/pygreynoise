import logging

from greynoise.api.base import Base

LOGGER = logging.getLogger(__name__)


class Stats(Base):

    EP_GNQL_STATS = "experimental/gnql/stats"

    def __call__(self, query):
        """Run GNQL stats query."""
        LOGGER.debug("Running GNQL stats query: %s...", query)
        response = self._request(self.EP_GNQL_STATS, params={"query": query})
        return response
