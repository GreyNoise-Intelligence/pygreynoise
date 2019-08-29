import logging

from greynoise.api.base import Base

LOGGER = logging.getLogger(__name__)


class GNQL(Base):

    EP_GNQL = "experimental/gnql"
    EP_GNQL_STATS = "experimental/gnql/stats"

    def query(self, query):
        """Run GNQL query."""
        LOGGER.debug("Running GNQL query: %s...", query)
        response = self._request(self.EP_GNQL, params={"query": query})
        return response

    def stats(self, query):
        """Run GNQL stats query."""
        LOGGER.debug("Running GNQL stats query: %s...", query)
        response = self._request(self.EP_GNQL_STATS, params={"query": query})
        return response
