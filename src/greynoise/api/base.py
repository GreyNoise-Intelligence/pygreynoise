import requests

from greynoise.exceptions import RateLimitError, RequestFailure

# Cache configuration
MAX_SIZE = 1000
TTL = 3600


class Base(object):
    CLIENT_VERSION = "0.2.2"
    API_VERSION = "v2"
    BASE_URL = "https://enterprise.api.greynoise.io"

    SESSION = requests.Session()

    def __init__(self, api_key=None, timeout=7, use_cache=True):
        self.api_key = api_key
        self.timeout = timeout
        self.use_cache = use_cache

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
        response = self.SESSION.get(
            url, headers=headers, timeout=self.timeout, params=params, json=json
        )

        body = response.json()
        if response.status_code == 429:
            raise RateLimitError()
        if not 200 <= response.status_code < 300:
            raise RequestFailure(response.status_code, body)

        return body
