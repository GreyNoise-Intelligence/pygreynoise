import logging

from greynoise.api.base import Base

LOGGER = logging.getLogger(__name__)


class Query(Base):

    EP_GNQL = "experimental/gnql"

    def __call__(self, query):
        """Run GNQL query."""
        LOGGER.debug("Running GNQL query: %s...", query)
        response = self._request(self.EP_GNQL, params={"query": query})
        return response
