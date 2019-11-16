"""GreyNoise API client test cases."""

import pytest
from mock import Mock, call, patch

from greynoise.api import GreyNoise
from greynoise.exceptions import RateLimitError, RequestFailure


@pytest.fixture
def client():
    """API client fixture."""
    client = GreyNoise(api_key="<api_key>")
    client.IP_QUICK_CHECK_CACHE.clear()
    client.IP_CONTEXT_CACHE.clear()
    yield client


@pytest.fixture
def client_without_cache():
    """API client without cache fixture."""
    client = GreyNoise(api_key="<api_key>", use_cache=False)
    yield client


class TestInit(object):
    """GreyNoise client initialization."""

    def test_with_api_key(self):
        """API parameter is passed."""
        config = {"api_key": "<api_key>", "timeout": "<timeout>"}
        with patch("greynoise.api.load_config") as load_config:
            client = GreyNoise(**config)
            assert client.api_key == config["api_key"]
            assert client.timeout == config["timeout"]
            load_config.assert_not_called()

    def test_without_api_key(self):
        """API parameter is not passed."""
        config = {"api_key": "<api_key>", "timeout": "<timeout>"}
        with patch("greynoise.api.load_config") as load_config:
            load_config.return_value = config
            client = GreyNoise()
            assert client.api_key == config["api_key"]
            assert client.timeout == config["timeout"]
            load_config.assert_called()


class TestRequest(object):
    """GreyNoise client _request method test cases."""

    @pytest.mark.parametrize("status_code", (400, 500))
    def test_status_code_failure(self, client, status_code):
        """Exception is raised on response status code failure."""
        client.session = Mock()
        response = client.session.get()
        response.status_code = status_code
        response.headers.get.return_value = "application/json"
        with pytest.raises(RequestFailure):
            client._request("endpoint")

    def test_rate_limit_error(self, client):
        """Exception is raised on rate limit response."""
        client.session = Mock()
        response = client.session.get()
        response.headers.get.return_value = "application/json"
        response.status_code = 429
        with pytest.raises(RateLimitError):
            client._request("endpoint")

    def test_json(self, client):
        """Response's json payload is returned."""
        expected_response = {"expected": "response"}
        client.session = Mock()
        response = client.session.get()
        response.status_code = 200
        response.headers.get.return_value = "application/json"
        response.json.return_value = expected_response

        response = client._request("endpoint")
        assert response == expected_response

    def test_text(self, client):
        """Response's text payload is returned."""
        expected_response = "<response>"
        client.session = Mock()
        response = client.session.get()
        response.status_code = 200
        response.headers.get.return_value = "text/plain"
        response.text = expected_response

        response = client._request("endpoint")
        assert response == expected_response


class TestNotImplemented(object):
    """Greynoise client not implemented test cases."""

    def test_not_implemented(self, client):
        client._request = Mock()
        client.not_implemented("<subcommand>")


class TestFilter(object):
    """GreyNoise client filter test cases."""

    @pytest.fixture
    def client(self, client):
        """API client fixture with quick method mocked."""
        client.quick = Mock(
            return_value=[
                {"ip": "0.0.0.0", "noise": True},
                {"ip": "255.255.255.255", "noise": False},
            ]
        )
        yield client

    @pytest.mark.parametrize(
        "text, expected_output",
        [
            (
                "0.0.0.0\n255.255.255.255\nnot an ip address",
                "<not-noise>255.255.255.255</not-noise>\nnot an ip address",
            ),
            (
                "0.0.0.0 255.255.255.255\nnot an ip address",
                (
                    "<noise>0.0.0.0</noise> <not-noise>255.255.255.255</not-noise>\n"
                    "not an ip address"
                ),
            ),
        ],
    )
    def test_discard_noise(self, client, text, expected_output):
        """Discard lines with noisy IP addresses."""
        output = "".join(client.filter(text))
        assert output == expected_output

    @pytest.mark.parametrize(
        "text, expected_output",
        [
            (
                "0.0.0.0\n255.255.255.255\nnot an ip address",
                "<noise>0.0.0.0</noise>\n",
            ),
            ("0.0.0.0 255.255.255.255\nnot an ip address", "",),
        ],
    )
    def test_select_noise(self, client, text, expected_output):
        """Select lines with noisy IP addresses."""
        output = "".join(client.filter(text, noise_only=True))
        assert output == expected_output


class TestInteresting(object):
    """GreyNoise client "interesting" IP test cases."""

    def test_interesting(self, client):
        """Report an IP as "interesting"."""
        ip_address = "0.0.0.0"
        expected_response = {}
        client._request = Mock(return_value=expected_response)
        response = client.interesting(ip_address)
        client._request.assert_called_with(
            "interesting/{}".format(ip_address), method="post"
        )
        assert response == expected_response

    def test_invalid_ip(self, client):
        """Report an invalid IP as "interesting"."""
        invalid_ip = "not an ip address"
        client._request = Mock()

        with pytest.raises(ValueError) as exception:
            client.ip(invalid_ip)
        assert str(exception.value) == "Invalid IP address: {!r}".format(invalid_ip)

        client._request.assert_not_called()


class TestIP(object):
    """GreyNoise client IP context test cases."""

    def test_ip(self, client):
        """Get IP address information."""
        ip_address = "0.0.0.0"
        expected_response = {}

        client._request = Mock(return_value=expected_response)
        response = client.ip(ip_address)
        client._request.assert_called_with("noise/context/{}".format(ip_address))
        assert response == expected_response

    def test_ip_with_cache(self, client):
        """Get IP address information with cache."""
        ip_address = "0.0.0.0"
        expected_response = {}

        client._request = Mock(return_value=expected_response)
        client.ip(ip_address)
        client._request.assert_called_with("noise/context/{}".format(ip_address))

        client._request.reset_mock()
        client.ip(ip_address)
        client._request.assert_not_called()

    def test_ip_without_cache(self, client_without_cache):
        """Get IP address information without cache."""
        client = client_without_cache
        ip_address = "0.0.0.0"
        expected_response = {}

        client._request = Mock(return_value=expected_response)
        client.ip(ip_address)
        client._request.assert_called_with("noise/context/{}".format(ip_address))

        client._request.reset_mock()
        client.ip(ip_address)
        client._request.assert_called_with("noise/context/{}".format(ip_address))

    def test_invalid_ip(self, client):
        """Get invalid IP address information."""
        invalid_ip = "not an ip address"
        client._request = Mock()

        with pytest.raises(ValueError) as exception:
            client.ip(invalid_ip)
        assert str(exception.value) == "Invalid IP address: {!r}".format(invalid_ip)

        client._request.assert_not_called()


class TestQuick(object):
    """GreyNoise client IP quick check test cases."""

    @pytest.mark.parametrize(
        "ip_addresses, expected_request, mock_response, expected_results",
        (
            (
                ["0.0.0.0", "127.0.0.1", "10.0.0.0"],
                call(
                    "noise/multi/quick",
                    json={"ips": ["0.0.0.0", "127.0.0.1", "10.0.0.0"]},
                ),
                [
                    {"code": "0x00", "ip": "0.0.0.0", "noise": False},
                    {"code": "0x01", "ip": "127.0.0.1", "noise": False},
                    {"code": "0x99", "ip": "10.0.0.0", "noise": False},
                ],
                [
                    {
                        "code": "0x00",
                        "code_message": (
                            "IP has never been observed scanning the Internet"
                        ),
                        "ip": "0.0.0.0",
                        "noise": False,
                    },
                    {
                        "code": "0x01",
                        "code_message": (
                            "IP has been observed by the GreyNoise sensor network"
                        ),
                        "ip": "127.0.0.1",
                        "noise": False,
                    },
                    {
                        "code": "0x99",
                        "code_message": "Code message unknown: 0x99",
                        "ip": "10.0.0.0",
                        "noise": False,
                    },
                ],
            ),
            (
                ["0.0.0.0", "not-an-ip", "10.0.0.0"],
                call("noise/multi/quick", json={"ips": ["0.0.0.0", "10.0.0.0"]}),
                [
                    {"code": "0x00", "ip": "0.0.0.0", "noise": False},
                    {"code": "0x99", "ip": "10.0.0.0", "noise": False},
                ],
                [
                    {
                        "code": "0x00",
                        "code_message": (
                            "IP has never been observed scanning the Internet"
                        ),
                        "ip": "0.0.0.0",
                        "noise": False,
                    },
                    {
                        "code": "0x99",
                        "code_message": "Code message unknown: 0x99",
                        "ip": "10.0.0.0",
                        "noise": False,
                    },
                ],
            ),
            (
                "0.0.0.0",
                call("noise/multi/quick", json={"ips": ["0.0.0.0"]}),
                {"code": "0x00", "ip": "0.0.0.0", "noise": False},
                [
                    {
                        "code": "0x00",
                        "code_message": (
                            "IP has never been observed scanning the Internet"
                        ),
                        "ip": "0.0.0.0",
                        "noise": False,
                    }
                ],
            ),
            (
                ["not-an-ip#1", "0.0.0.0", "not-an-ip#2"],
                call("noise/multi/quick", json={"ips": ["0.0.0.0"]}),
                {"code": "0x00", "ip": "0.0.0.0", "noise": False},
                [
                    {
                        "code": "0x00",
                        "code_message": (
                            "IP has never been observed scanning the Internet"
                        ),
                        "ip": "0.0.0.0",
                        "noise": False,
                    }
                ],
            ),
        ),
    )
    def test_quick(
        self, client, ip_addresses, expected_request, mock_response, expected_results
    ):
        """Get IP address noise status."""
        client._request = Mock(return_value=mock_response)
        results = client.quick(ip_addresses)
        client._request.assert_has_calls([expected_request])
        assert results == expected_results

    @pytest.mark.parametrize("ip_addresses", ([], ["not-an-ip"], "not-an-ip"))
    def test_empty_request(self, client, ip_addresses):
        """IP addresses is empty or only contains invalid IP addresses."""
        client._request = Mock()
        results = client.quick(ip_addresses)
        client._request.assert_not_called()
        assert results == []

    @pytest.mark.parametrize(
        "ip_addresses, expected_request, mock_response",
        (
            (
                ["0.0.0.0", "127.0.0.1", "10.0.0.0"],
                call(
                    "noise/multi/quick",
                    json={"ips": ["0.0.0.0", "127.0.0.1", "10.0.0.0"]},
                ),
                [
                    {"code": "0x00", "ip": "0.0.0.0", "noise": False},
                    {"code": "0x01", "ip": "127.0.0.1", "noise": False},
                    {"code": "0x99", "ip": "10.0.0.0", "noise": False},
                ],
            ),
            (
                ["0.0.0.0", "not-an-ip", "10.0.0.0"],
                call("noise/multi/quick", json={"ips": ["0.0.0.0", "10.0.0.0"]}),
                [
                    {"code": "0x00", "ip": "0.0.0.0", "noise": False},
                    {"code": "0x99", "ip": "10.0.0.0", "noise": False},
                ],
            ),
            (
                "0.0.0.0",
                call("noise/multi/quick", json={"ips": ["0.0.0.0"]}),
                {"code": "0x00", "ip": "0.0.0.0", "noise": False},
            ),
            (
                ["not-an-ip#1", "0.0.0.0", "not-an-ip#2"],
                call("noise/multi/quick", json={"ips": ["0.0.0.0"]}),
                {"code": "0x00", "ip": "0.0.0.0", "noise": False},
            ),
        ),
    )
    def test_quick_with_cache(
        self, client, ip_addresses, expected_request, mock_response
    ):
        """Get IP addresses noise status with cache."""
        client._request = Mock(return_value=mock_response)
        client.quick(ip_addresses)
        client._request.assert_has_calls([expected_request])

        client._request.reset_mock()
        client.quick(ip_addresses)
        client._request.assert_not_called()

    @pytest.mark.parametrize(
        "ip_addresses, expected_request, mock_response",
        (
            (
                ["0.0.0.0", "127.0.0.1", "10.0.0.0"],
                call(
                    "noise/multi/quick",
                    json={"ips": ["0.0.0.0", "127.0.0.1", "10.0.0.0"]},
                ),
                [
                    {"code": "0x00", "ip": "0.0.0.0", "noise": False},
                    {"code": "0x01", "ip": "127.0.0.1", "noise": False},
                    {"code": "0x99", "ip": "10.0.0.0", "noise": False},
                ],
            ),
            (
                ["0.0.0.0", "not-an-ip", "10.0.0.0"],
                call("noise/multi/quick", json={"ips": ["0.0.0.0", "10.0.0.0"]}),
                [
                    {"code": "0x00", "ip": "0.0.0.0", "noise": False},
                    {"code": "0x99", "ip": "10.0.0.0", "noise": False},
                ],
            ),
            (
                "0.0.0.0",
                call("noise/multi/quick", json={"ips": ["0.0.0.0"]}),
                {"code": "0x00", "ip": "0.0.0.0", "noise": False},
            ),
            (
                ["not-an-ip#1", "0.0.0.0", "not-an-ip#2"],
                call("noise/multi/quick", json={"ips": ["0.0.0.0"]}),
                {"code": "0x00", "ip": "0.0.0.0", "noise": False},
            ),
        ),
    )
    def test_quick_without_cache(
        self, client_without_cache, ip_addresses, expected_request, mock_response
    ):
        """Get IP addresses noise status with cache."""
        client = client_without_cache
        client._request = Mock(return_value=mock_response)
        client.quick(ip_addresses)
        client._request.assert_has_calls([expected_request])

        client._request.reset_mock()
        client.quick(ip_addresses)
        client._request.assert_has_calls([expected_request])


class TestQuery(object):
    """GreyNoise client run GNQL query test cases."""

    def test_query(self, client):
        """Run GNQL query."""
        query = "<query>"
        expected_response = []

        client._request = Mock(return_value=expected_response)
        response = client.query(query)
        client._request.assert_called_with("experimental/gnql", params={"query": query})
        assert response == expected_response

    def test_query_with_size_and_scroll(self, client):
        """Run GNQL query with size and scroll parameters."""
        query = "<query>"
        expected_response = []

        client._request = Mock(return_value=expected_response)
        response = client.query(query, size=5, scroll="scroll")
        client._request.assert_called_with(
            "experimental/gnql", params={"query": query, "size": 5, "scroll": "scroll"}
        )
        assert response == expected_response


class TestStats(object):
    """GreyNoise client run GNQL stats query test cases."""

    def test_stats(self, client):
        """Run GNQL stats query."""
        query = "<query>"
        expected_response = []

        client._request = Mock(return_value=expected_response)
        response = client.stats(query)
        client._request.assert_called_with(
            "experimental/gnql/stats", params={"query": query}
        )
        assert response == expected_response
