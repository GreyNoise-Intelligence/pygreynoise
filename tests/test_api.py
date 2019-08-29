"""GreyNoise API client test cases."""

import pytest
from mock import Mock, patch

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
        expected = "<api_key>"
        with patch("greynoise.api.load_config") as load_config:
            client = GreyNoise(api_key=expected)
            assert client.api_key == expected
            load_config.assert_not_called()

    def test_without_api_key(self):
        """API parameter is not passed."""
        expected = "<api_key>"
        with patch("greynoise.api.load_config") as load_config:
            load_config.return_value = {"api_key": expected}
            client = GreyNoise()
            assert client.api_key == expected
            load_config.assert_called()


class TestRequest(object):
    """GreyNoise client _request method test cases."""

    @pytest.mark.parametrize("status_code", (100, 300, 400, 500))
    def test_status_code_failure(self, client, status_code):
        """Exception is raised on response status code failure."""
        client.session = Mock()
        client.session.get().status_code = status_code
        with pytest.raises(RequestFailure):
            client._request("endpoint")

    def test_rate_limit_error(self, client):
        """Exception is raised on rate limit response."""
        client.session = Mock()
        client.session.get().status_code = 429
        with pytest.raises(RateLimitError):
            client._request("endpoint")

    def test_json(self, client):
        """Response's json payload is returned."""
        expected_response = {"expected": "response"}
        client.session = Mock()
        client.session.get().status_code = 200
        client.session.get().json.return_value = expected_response

        response = client._request("endpoint")
        assert response == expected_response


class TestGetContext(object):
    """GreyNoise client IP context test cases."""

    def test_get_context(self, client):
        """Get IP address information."""
        ip_address = "0.0.0.0"
        expected_response = {}

        client._request = Mock(return_value=expected_response)
        response = client.get_context(ip_address)
        client._request.assert_called_with("noise/context/{}".format(ip_address))
        assert response == expected_response

    def test_get_context_with_cache(self, client):
        """Get IP address information with cache."""
        ip_address = "0.0.0.0"
        expected_response = {}

        client._request = Mock(return_value=expected_response)
        client.get_context(ip_address)
        client._request.assert_called_with("noise/context/{}".format(ip_address))

        client._request.reset_mock()
        client.get_context(ip_address)
        client._request.assert_not_called()

    def test_get_context_without_cache(self, client_without_cache):
        """Get IP address information without cache."""
        client = client_without_cache
        ip_address = "0.0.0.0"
        expected_response = {}

        client._request = Mock(return_value=expected_response)
        client.get_context(ip_address)
        client._request.assert_called_with("noise/context/{}".format(ip_address))

        client._request.reset_mock()
        client.get_context(ip_address)
        client._request.assert_called_with("noise/context/{}".format(ip_address))

    def test_get_context_invalid_ip(self, client):
        """Get invalid IP address information."""
        invalid_ip = "not an ip address"
        client._request = Mock()

        with pytest.raises(ValueError) as exception:
            client.get_context(invalid_ip)
        assert str(exception.value) == "Invalid IP address: {!r}".format(invalid_ip)

        client._request.assert_not_called()


class TestGetNoiseStatus(object):
    """GreyNoise client IP quick check test cases."""

    @pytest.mark.parametrize(
        "ip_address, mock_response, expected_results",
        (
            (
                "0.0.0.0",
                {"code": "0x00", "ip": "0.0.0.0", "noise": False},
                {
                    "code": "0x00",
                    "code_message": "IP has never been observed scanning the Internet",
                    "ip": "0.0.0.0",
                    "noise": False,
                },
            ),
            (
                "127.0.0.1",
                {"code": "0x01", "ip": "127.0.0.1", "noise": False},
                {
                    "code": "0x01",
                    "code_message": (
                        "IP has been observed by the GreyNoise sensor network"
                    ),
                    "ip": "127.0.0.1",
                    "noise": False,
                },
            ),
            (
                "10.0.0.0",
                {"code": "0x99", "ip": "10.0.0.0", "noise": True},
                {
                    "code": "0x99",
                    "code_message": "Code message unknown: 0x99",
                    "ip": "10.0.0.0",
                    "noise": True,
                },
            ),
        ),
    )
    def test_get_noise_status(
        self, client, ip_address, mock_response, expected_results
    ):
        """Get IP address noise status."""
        client._request = Mock(return_value=mock_response)
        response = client.get_noise_status(ip_address)
        client._request.assert_called_with("noise/quick/{}".format(ip_address))
        assert response == expected_results

    @pytest.mark.parametrize(
        "ip_address, mock_response",
        (
            (
                "0.0.0.0",
                {
                    "code": "0x00",
                    "code_message": "IP has never been observed scanning the Internet",
                    "ip": "0.0.0.0",
                    "noise": False,
                },
            ),
        ),
    )
    def test_get_noise_status_with_cache(self, client, ip_address, mock_response):
        """Get IP address noise status with cache."""
        client._request = Mock(return_value=mock_response)
        client.get_noise_status(ip_address)
        client._request.assert_called_with("noise/quick/{}".format(ip_address))

        client._request.reset_mock()
        client.get_noise_status(ip_address)
        client._request.assert_not_called()

    @pytest.mark.parametrize(
        "ip_address, mock_response",
        (
            (
                "0.0.0.0",
                {
                    "code": "0x00",
                    "code_message": "IP has never been observed scanning the Internet",
                    "ip": "0.0.0.0",
                    "noise": False,
                },
            ),
        ),
    )
    def test_get_noise_status_without_cache(
        self, client_without_cache, ip_address, mock_response
    ):
        """Get IP address noise status without cache."""
        client = client_without_cache
        client._request = Mock(return_value=mock_response)
        client.get_noise_status(ip_address)
        client._request.assert_called_with("noise/quick/{}".format(ip_address))

        client._request.reset_mock()
        client.get_noise_status(ip_address)
        client._request.assert_called_with("noise/quick/{}".format(ip_address))

    def test_get_noise_status_invalid_ip(self, client):
        """Get invalid IP address noise status."""
        invalid_ip = "not an ip address"
        client._request = Mock()

        with pytest.raises(ValueError) as exception:
            client.get_noise_status(invalid_ip)
        assert str(exception.value) == "Invalid IP address: {!r}".format(invalid_ip)

        client._request.assert_not_called()


class TestGetNoiseStatusBulk(object):
    """GreyNoise client IP multi quick check test cases."""

    @pytest.mark.parametrize(
        "ip_addresses, filtered_ip_addresses, mock_response, expected_results",
        (
            (
                ["0.0.0.0", "127.0.0.1", "10.0.0.0"],
                ["0.0.0.0", "127.0.0.1", "10.0.0.0"],
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
                ["not-an-ip#1", "0.0.0.0", "not-an-ip#2"],
                ["0.0.0.0"],
                [{"code": "0x00", "ip": "0.0.0.0", "noise": False}],
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
    def test_get_noise_status_bulk(
        self,
        client,
        ip_addresses,
        filtered_ip_addresses,
        mock_response,
        expected_results,
    ):
        """Get IP address noise status."""
        client._request = Mock(return_value=mock_response)
        results = client.get_noise_status_bulk(ip_addresses)
        client._request.assert_called_with(
            "noise/multi/quick", json={"ips": filtered_ip_addresses}
        )
        assert results == expected_results

    @pytest.mark.parametrize(
        "ip_addresses, filtered_ip_addresses, mock_response",
        (
            (
                ["0.0.0.0", "127.0.0.1", "10.0.0.0"],
                ["0.0.0.0", "127.0.0.1", "10.0.0.0"],
                [
                    {"code": "0x00", "ip": "0.0.0.0", "noise": False},
                    {"code": "0x01", "ip": "127.0.0.1", "noise": False},
                    {"code": "0x99", "ip": "10.0.0.0", "noise": False},
                ],
            ),
        ),
    )
    def test_get_noise_status_bulk_with_cache(
        self, client, ip_addresses, filtered_ip_addresses, mock_response
    ):
        """Get IP addresses noise status with cache."""
        client._request = Mock(return_value=mock_response)
        client.get_noise_status_bulk(ip_addresses)
        client._request.assert_called_with(
            "noise/multi/quick", json={"ips": filtered_ip_addresses}
        )

        client._request.reset_mock()
        client.get_noise_status_bulk(ip_addresses)
        client._request.assert_not_called()

    @pytest.mark.parametrize(
        "ip_addresses, filtered_ip_addresses, mock_response",
        (
            (
                ["0.0.0.0", "127.0.0.1", "10.0.0.0"],
                ["0.0.0.0", "127.0.0.1", "10.0.0.0"],
                [
                    {"code": "0x00", "ip": "0.0.0.0", "noise": False},
                    {"code": "0x01", "ip": "127.0.0.1", "noise": False},
                    {"code": "0x99", "ip": "10.0.0.0", "noise": False},
                ],
            ),
        ),
    )
    def test_get_noise_status_bulk_without_cache(
        self, client_without_cache, ip_addresses, filtered_ip_addresses, mock_response
    ):
        """Get IP addresses noise status with cache."""
        client = client_without_cache
        client._request = Mock(return_value=mock_response)
        client.get_noise_status_bulk(ip_addresses)
        client._request.assert_called_with(
            "noise/multi/quick", json={"ips": filtered_ip_addresses}
        )

        client._request.reset_mock()
        client.get_noise_status_bulk(ip_addresses)
        client._request.assert_called_with(
            "noise/multi/quick", json={"ips": filtered_ip_addresses}
        )

    def test_get_noise_status_bulk_not_a_list(self, client):
        """ValueError raised when argument is not a list."""
        with pytest.raises(ValueError) as exception:
            client.get_noise_status_bulk("not a list")
        assert str(exception.value) == "`ip_addresses` must be a list"


class TestGetActors(object):
    """GreyNoise client actors test cases."""

    def test_get_actors(self, client):
        """Get actors scanning the Internet."""
        expected_response = [{"name": "<actor>", "ips": ["ip#1", "ip#2", "ip#3"]}]

        client._request = Mock(return_value=expected_response)
        actors = client.get_actors()
        client._request.assert_called_with("research/actors")
        assert actors == expected_response


class TestRunQuery(object):
    """GreyNoise client run GNQL query test cases."""

    def test_run_query(self, client):
        """Run GNQL query."""
        query = "<query>"
        expected_response = []

        client._request = Mock(return_value=expected_response)
        response = client.run_query(query)
        client._request.assert_called_with("experimental/gnql", params={"query": query})
        assert response == expected_response


class TestRunStatsQuery(object):
    """GreyNoise client run GNQL stats query test cases."""

    def test_run_query(self, client):
        """Run GNQL stats query."""
        query = "<query>"
        expected_response = []

        client._request = Mock(return_value=expected_response)
        response = client.run_stats_query(query)
        client._request.assert_called_with(
            "experimental/gnql/stats", params={"query": query}
        )
        assert response == expected_response
