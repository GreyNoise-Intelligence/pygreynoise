import requests


class GreyNoiseError(Exception):
    """Exception for GreyNoise API"""
    def __init__(self, message):
        self.message = message
        Exception.__init__(self, message)


class GreyNoiseNotFound(GreyNoiseError):
    def __init__(self):
        self.message = "No results for this query"
        GreyNoiseError.__init__(self, self.message)


class GreyNoise(object):
    """ Main GreyNoise class"""
    def __init__(self):
        self.ua = "PyGreyNoise"
        self.base_url = "http://api.greynoise.io:8888/v1/"

    def _request(self, path, params, type="GET"):
        headers = {'User-Agent': self.ua}
        if type == "GET":
            r = requests.get(
                self.base_url + path,
                headers=headers,
                params=params
            )
        else:
            r = requests.post(
                    self.base_url + path,
                    headers=headers,
                    data=params
            )

        if r.status_code == 200:
            if r.json()["status"] in ["ok", "exists"]:
                return r.json()
            else:
                if r.json()["status"] == "unknown":
                    raise GreyNoiseNotFound()
                else:
                    raise GreyNoiseError("Invalid status: %s" % r.json()["status"])
        else:
            raise GreyNoiseError("Invalid HTTP return code %i" % r.status_code)

    def tags(self):
        return self._request('query/list', {})["tags"]

    def query_ip(self, ip):
        return self._request('query/ip', {'ip': ip}, type="POST")['records']

    def query_tag(self, tag):
        return self._request('query/tag', {'tag': tag}, type="POST")['records']
