"""GreyNoise API client."""

from greynoise.api.actors import Actors
from greynoise.api.ip import IP
from greynoise.api.query import Query
from greynoise.api.quick import Quick
from greynoise.api.stats import Stats
from greynoise.util import load_config


class GreyNoise(object):

    """GreyNoise API client.

    :param api_key: Key use to access the API.
    :type api_key: str
    :param timeout: API requests timeout in seconds.
    :type timeout: int

    """

    def __init__(self, api_key=None, timeout=7):
        if api_key is None:
            api_key = load_config()["api_key"]

        self.actors = Actors(api_key, timeout)
        self.ip = IP(api_key, timeout)
        self.query = Query(api_key, timeout)
        self.quick = Quick(api_key, timeout)
        self.stats = Stats(api_key, timeout)
