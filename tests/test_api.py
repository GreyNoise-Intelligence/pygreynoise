"""GreyNoise API client test cases."""

from unittest.mock import Mock, call, patch

import pytest

from greynoise.api import APIConfig, GreyNoise
from greynoise.exceptions import RequestFailure


@pytest.fixture
def client():
    """API client fixture."""
    config = APIConfig(
        api_key="<api_key>",
        api_server="https://api.greynoise.io",
        timeout=120,
        offering="enterprise",
        proxy=None,
        integration_name="test",
        cache_max_size=1000000,
        cache_ttl=3600,
        use_cache=True,
    )
    client = GreyNoise(config)
    yield client


@pytest.fixture
def client_without_cache():
    """API client without cache fixture."""
    config = APIConfig(
        api_key="<api_key>",
        api_server="https://api.greynoise.io",
        timeout=120,
        offering="enterprise",
        proxy=None,
        integration_name="test",
        use_cache=False,
        cache_max_size=1000000,
        cache_ttl=3600,
    )
    client = GreyNoise(config)
    yield client


class TestInit(object):
    """GreyNoise client initialization test cases."""

    def test_with_api_key(self):
        """Initialize client with API key."""
        api_key = "api-key"
        config = APIConfig(
            api_key=api_key,
            api_server="https://api.greynoise.io",
            timeout=60,
            proxy=None,
            offering="enterprise",
            integration_name="greynoise-python",
            use_cache=True,
        )
        client = GreyNoise(config)
        assert client.config.api_key == api_key
        assert client.config.api_server == "https://api.greynoise.io"
        assert client.config.timeout == 60
        assert client.config.proxy is None
        assert client.config.offering == "enterprise"
        assert client.config.integration_name == "greynoise-python"
        assert client.config.use_cache is True

    def test_without_api_key(self):
        """Initialize client without API key."""
        config = APIConfig(
            api_key=None,
            api_server="https://api.greynoise.io",
            timeout=60,
            proxy=None,
            offering="enterprise",
            integration_name="greynoise-python",
            use_cache=True,
        )
        client = GreyNoise(config)
        assert client.config.api_key is None
        assert client.config.api_server == "https://api.greynoise.io"
        assert client.config.timeout == 60
        assert client.config.proxy is None
        assert client.config.offering == "enterprise"
        assert client.config.integration_name == "greynoise-python"
        assert client.config.use_cache is True


class TestRequest:
    """Test request method parameters."""

    def test_request_method_parameters(self, client):
        """Test that request method parameters are passed correctly."""
        client._request = Mock(return_value={"success": True})
        client.request("test-endpoint", method="get")
        client._request.assert_called_once_with(
            "test-endpoint",
            method="get",
            params=None,
            json=None,
            files=None,
            headers={"key": client.config.api_key, "Accept": "application/json"},
            proxy=None,
        )

    def test_request_method_parameters_with_params(self, client):
        """Test that parameters are passed correctly."""
        client._request = Mock(return_value={"success": True})
        client.request("test-endpoint", method="get", params={"test": "param"})
        client._request.assert_called_once_with(
            "test-endpoint",
            method="get",
            params={"test": "param"},
            json=None,
            files=None,
            headers={"key": client.config.api_key, "Accept": "application/json"},
            proxy=None,
        )

    def test_request_method_parameters_with_json(self, client):
        """Test that JSON data is passed correctly."""
        client._request = Mock(return_value={"success": True})
        client.request("test-endpoint", method="post", json={"test": "data"})
        client._request.assert_called_once_with(
            "test-endpoint",
            method="post",
            params=None,
            json={"test": "data"},
            files=None,
            headers={"key": client.config.api_key, "Accept": "application/json"},
            proxy=None,
        )

    def test_request_method_parameters_with_files(self, client):
        """Test that file data is passed correctly."""
        client._request = Mock(return_value={"success": True})
        client.request("test-endpoint", method="post", files={"test": "file"})
        client._request.assert_called_once_with(
            "test-endpoint",
            method="post",
            params=None,
            json=None,
            files={"test": "file"},
            headers={"key": client.config.api_key, "Accept": "application/json"},
            proxy=None,
        )


class TestNotImplemented(object):
    """Greynoise client not implemented test cases."""

    def test_not_implemented(self, client):
        client._request = Mock()
        client.not_implemented("<subcommand>")


class TestAnalyze(object):
    """Greynoise client analyze test cases."""

    @pytest.fixture
    def client(self, client):
        """API client fixture with analyze method mocked."""
        client.analyze = Mock(
            return_value={
                "count": 1,
                "query": ["1.2.2.1"],
                "stats": {
                    "actors": [{"actor": "<actor_1>", "count": 1}],
                    "classifications": [
                        {"classification": "<classification_1>", "count": 1},
                        {"classification": "<classification_2>", "count": 1},
                    ],
                    "countries": [
                        {"country": "<country_1>", "count": 1},
                        {"country": "<country_2>", "count": 1},
                    ],
                    "operating_systems": [
                        {"operating_system": "<operating_system_1>", "count": 1},
                        {"operating_system": "<operating_system_2>", "count": 1},
                    ],
                    "tags": [
                        {"tag": "<tag_1>", "count": 1},
                        {"tag": "<tag_2>", "count": 1},
                    ],
                },
                "summary": {
                    "ip_count": 1,
                    "noise_ip_count": 1,
                    "riot_ip_count": 0,
                    "not_noise_ip_count": 0,
                    "noise_ip_ratio": 1.00,
                    "riot_ip_ratio": 0.0,
                },
            }
        )
        yield client

    @pytest.mark.parametrize(
        "text, expected_output",
        (
            (
                "1.2.2.1",
                {
                    "count": 1,
                    "query": ["1.2.2.1"],
                    "stats": {
                        "actors": [{"actor": "<actor_1>", "count": 1}],
                        "classifications": [
                            {"classification": "<classification_1>", "count": 1},
                            {"classification": "<classification_2>", "count": 1},
                        ],
                        "countries": [
                            {"country": "<country_1>", "count": 1},
                            {"country": "<country_2>", "count": 1},
                        ],
                        "operating_systems": [
                            {"operating_system": "<operating_system_1>", "count": 1},
                            {"operating_system": "<operating_system_2>", "count": 1},
                        ],
                        "tags": [
                            {"tag": "<tag_1>", "count": 1},
                            {"tag": "<tag_2>", "count": 1},
                        ],
                    },
                    "summary": {
                        "ip_count": 1,
                        "noise_ip_count": 1,
                        "riot_ip_count": 0,
                        "not_noise_ip_count": 0,
                        "noise_ip_ratio": 1.00,
                        "riot_ip_ratio": 0.0,
                    },
                },
            ),
        ),
    )
    def test_analyze(self, client, text, expected_output):
        """Analyze input text."""
        output = client.analyze(text)
        assert output == expected_output


class TestFilter(object):
    """GreyNoise client filter test cases."""

    @pytest.fixture
    def client(self, client):
        """API client fixture with quick method mocked."""
        client.quick = Mock(
            return_value=[
                {"ip": "8.8.8.8", "noise": True, "riot": True},
                {"ip": "123.123.123.123", "noise": False, "riot": False},
            ]
        )
        yield client

    @pytest.mark.parametrize(
        "text, expected_output",
        [
            (
                "8.8.8.8\n123.123.123.123\nnot an ip address",
                "<not-noise>123.123.123.123</not-noise>\nnot an ip address",
            ),
            (
                "8.8.8.8 123.123.123.123\nnot an ip address",
                (
                    "<noise>8.8.8.8</noise> <not-noise>123.123.123.123</not-noise>\n"
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
                "8.8.8.8\n123.123.123.123\nnot an ip address",
                "<noise>8.8.8.8</noise>\n",
            ),
            (
                "8.8.8.8 123.123.123.123\nnot an ip address",
                "",
            ),
        ],
    )
    def test_select_noise(self, client, text, expected_output):
        """Select lines with noisy IP addresses."""
        output = "".join(client.filter(text, noise_only=True))
        assert output == expected_output


class TestIP(object):
    """GreyNoise client IP context test cases."""

    def test_ip(self, client):
        """Get IP address information."""
        ip_address = "8.8.8.8"
        expected_response = {}

        client._request = Mock(return_value=expected_response)
        response = client.ip(ip_address)
        client._request.assert_called_with("v3/ip/{}".format(ip_address))
        assert response == expected_response

    def test_ip_with_cache(self, client):
        """Get IP address information with cache."""
        ip_address = "8.8.8.8"
        expected_response = {}

        client._request = Mock(return_value=expected_response)
        client.ip(ip_address)
        client._request.assert_called_with("v3/ip/{}".format(ip_address))

        client._request.reset_mock()
        client.ip(ip_address)
        client._request.assert_not_called()

    def test_ip_without_cache(self, client_without_cache):
        """Get IP address information without cache."""
        client = client_without_cache
        ip_address = "8.8.8.8"
        expected_response = {}

        client._request = Mock(return_value=expected_response)
        client.ip(ip_address)
        client._request.assert_called_with("v3/ip/{}".format(ip_address))

        client._request.reset_mock()
        client.ip(ip_address)
        client._request.assert_called_with("v3/ip/{}".format(ip_address))

    def test_invalid_ip(self, client):
        """Get invalid IP address information."""
        invalid_ip = "not an ip address"
        client._request = Mock()

        with pytest.raises(ValueError) as exception:
            client.ip(invalid_ip)
        assert str(exception.value) == "Invalid IP address: {!r}".format(invalid_ip)

        client._request.assert_not_called()


class TestQuick:
    """Test quick lookup functionality."""

    @pytest.mark.parametrize(
        "ip_addresses, expected_request, mock_response, expected_results",
        (
            (
                ["8.8.8.8", "67.68.68.79", "123.123.123.123"],
                call(
                    "v3/ip?quick=true",
                    method="post",
                    json={"ips": ["8.8.8.8", "67.68.68.79", "123.123.123.123"]},
                ),
                {
                    "data": [
                        {"code": "0x00", "ip": "8.8.8.8", "noise": False},
                        {"code": "0x01", "ip": "67.68.68.79", "noise": False},
                        {"code": "0x99", "ip": "123.123.123.123", "noise": False},
                    ]
                },
                [
                    {"code": "0x00", "ip": "8.8.8.8", "noise": False},
                    {"code": "0x01", "ip": "67.68.68.79", "noise": False},
                    {"code": "0x99", "ip": "123.123.123.123", "noise": False},
                ],
            ),
            (
                ["8.8.8.8", "not-an-ip", "123.123.123.123"],
                call(
                    "v3/ip?quick=true",
                    method="post",
                    json={"ips": ["8.8.8.8", "123.123.123.123"]},
                ),
                {
                    "data": [
                        {"code": "0x00", "ip": "8.8.8.8", "noise": False},
                        {"code": "0x99", "ip": "123.123.123.123", "noise": False},
                    ]
                },
                [
                    {"code": "0x00", "ip": "8.8.8.8", "noise": False},
                    {"code": "0x99", "ip": "123.123.123.123", "noise": False},
                ],
            ),
            (
                "8.8.8.8",
                call("v3/ip?quick=true", method="post", json={"ips": ["8.8.8.8"]}),
                {"data": [{"code": "0x00", "ip": "8.8.8.8", "noise": False}]},
                [{"code": "0x00", "ip": "8.8.8.8", "noise": False}],
            ),
            (
                ["not-an-ip#1", "8.8.8.8", "not-an-ip#2"],
                call("v3/ip?quick=true", method="post", json={"ips": ["8.8.8.8"]}),
                {
                    "data": [
                        {
                            "ip": "8.8.8.8",
                            "business_service_intelligence": {"found": False},
                        }
                    ],
                },
                [{"ip": "8.8.8.8", "business_service_intelligence": {"found": False}}],
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

    @pytest.mark.parametrize(
        "ip_addresses, expected_request, mock_response",
        (
            (
                ["8.8.8.8", "67.68.68.79", "123.123.123.123"],
                call(
                    "v3/ip?quick=true",
                    method="post",
                    json={"ips": ["8.8.8.8", "67.68.68.79", "123.123.123.123"]},
                ),
                {
                    "data": [
                        {
                            "ip": "8.8.8.8",
                            "business_service_intelligence": {"found": False},
                        },
                        {
                            "ip": "67.68.68.79",
                            "business_service_intelligence": {"found": False},
                        },
                        {
                            "ip": "123.123.123.123",
                            "business_service_intelligence": {"found": False},
                        },
                    ]
                },
            ),
            (
                ["8.8.8.8", "not-an-ip", "123.123.123.123"],
                call(
                    "v3/ip?quick=true",
                    method="post",
                    json={"ips": ["8.8.8.8", "123.123.123.123"]},
                ),
                {
                    "data": [
                        {
                            "ip": "8.8.8.8",
                            "business_service_intelligence": {"found": False},
                        },
                        {
                            "ip": "123.123.123.123",
                            "business_service_intelligence": {"found": False},
                        },
                    ]
                },
            ),
            (
                "8.8.8.8",
                call("v3/ip?quick=true", method="post", json={"ips": ["8.8.8.8"]}),
                {
                    "data": [
                        {
                            "ip": "8.8.8.8",
                            "business_service_intelligence": {"found": False},
                        }
                    ]
                },
            ),
            (
                ["not-an-ip#1", "8.8.8.8", "not-an-ip#2"],
                call("v3/ip?quick=true", method="post", json={"ips": ["8.8.8.8"]}),
                {
                    "data": [
                        {
                            "ip": "8.8.8.8",
                            "business_service_intelligence": {"found": False},
                        }
                    ]
                },
            ),
        ),
    )
    def test_quick_with_cache(
        self, client, ip_addresses, expected_request, mock_response
    ):
        """Get IP addresses noise status with cache."""
        # First call should hit the API
        client._request = Mock(return_value=mock_response)
        first_results = client.quick(ip_addresses)
        client._request.assert_has_calls([expected_request])

        # Reset the mock
        client._request.reset_mock()

        # Second call should use cache
        second_results = client.quick(ip_addresses)
        client._request.assert_not_called()

        # Results should be the same
        assert first_results == second_results

        # Verify cache contents
        if isinstance(ip_addresses, str):
            ip_addresses = [ip_addresses]
        valid_ips = [
            ip
            for ip in ip_addresses
            if ip != "not-an-ip" and not ip.startswith("not-an-ip")
        ]
        for ip in valid_ips:
            assert ip in client.ip_quick_check_cache
            assert client.ip_quick_check_cache[ip] == next(
                (item for item in first_results if item["ip"] == ip), None
            )

    @pytest.mark.parametrize(
        "ip_addresses, expected_request, mock_response",
        (
            (
                ["8.8.8.8", "67.68.68.79", "123.123.123.123"],
                call(
                    "v3/ip?quick=true",
                    method="post",
                    json={"ips": ["8.8.8.8", "67.68.68.79", "123.123.123.123"]},
                ),
                {
                    "data": [
                        {
                            "ip": "8.8.8.8",
                            "business_service_intelligence": {"found": False},
                        },
                        {
                            "ip": "67.68.68.79",
                            "business_service_intelligence": {"found": False},
                        },
                        {
                            "ip": "123.123.123.123",
                            "business_service_intelligence": {"found": False},
                        },
                    ]
                },
            ),
            (
                ["8.8.8.8", "not-an-ip", "123.123.123.123"],
                call(
                    "v3/ip?quick=true",
                    method="post",
                    json={"ips": ["8.8.8.8", "123.123.123.123"]},
                ),
                {
                    "data": [
                        {
                            "ip": "8.8.8.8",
                            "business_service_intelligence": {"found": False},
                        },
                        {
                            "ip": "123.123.123.123",
                            "business_service_intelligence": {"found": False},
                        },
                    ]
                },
            ),
            (
                "8.8.8.8",
                call("v3/ip?quick=true", method="post", json={"ips": ["8.8.8.8"]}),
                {
                    "data": [
                        {
                            "ip": "8.8.8.8",
                            "business_service_intelligence": {"found": False},
                        }
                    ]
                },
            ),
            (
                ["not-an-ip#1", "8.8.8.8", "not-an-ip#2"],
                call("v3/ip?quick=true", method="post", json={"ips": ["8.8.8.8"]}),
                {
                    "data": [
                        {
                            "ip": "8.8.8.8",
                            "business_service_intelligence": {"found": False},
                        }
                    ]
                },
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


class TestSensorActivity(object):
    """GreyNoise client run Sensor Activity test cases."""

    @pytest.fixture
    def client(self, client):
        """API client fixture with analyze method mocked."""
        client.sensor_activity = Mock(
            return_value=[
                {
                    "bytes": 1,
                    "destination_ip": "1.2.2.1",
                    "destination_port": 1234,
                    "http_uri": "",
                    "packets": 3,
                    "persona_id": "aaa-aa-aa-aa-aaaa",
                    "protocols": ["tcp"],
                    "sensor_id": "aaa-aa-aa-aa-aaaa",
                    "session_id": "asdfasdfs",
                    "source_ip": "1.2.2.1",
                    "source_port": 1234,
                    "start_time": "2024-06-09T23:56:57.51Z",
                    "stop_time": "2024-06-09T23:56:58.037Z",
                }
            ]
        )

        yield client

    def test_sensor_activity(self, client):
        """Run Sensor Activity."""
        workspace_id = "workspace_id"
        expected_response = [
            {
                "bytes": 1,
                "destination_ip": "1.2.2.1",
                "destination_port": 1234,
                "http_uri": "",
                "packets": 3,
                "persona_id": "aaa-aa-aa-aa-aaaa",
                "protocols": ["tcp"],
                "sensor_id": "aaa-aa-aa-aa-aaaa",
                "session_id": "asdfasdfs",
                "source_ip": "1.2.2.1",
                "source_port": 1234,
                "start_time": "2024-06-09T23:56:57.51Z",
                "stop_time": "2024-06-09T23:56:58.037Z",
            }
        ]
        response = client.sensor_activity(
            workspace_id=workspace_id, include_headers=False
        )

        assert response == expected_response

    def test_query_with_size_and_scroll(self, client):
        """Run Sensor Activity with size and scroll parameters."""
        workspace_id = "workspace_id"
        expected_response = [
            {
                "bytes": 1,
                "destination_ip": "1.2.2.1",
                "destination_port": 1234,
                "http_uri": "",
                "packets": 3,
                "persona_id": "aaa-aa-aa-aa-aaaa",
                "protocols": ["tcp"],
                "sensor_id": "aaa-aa-aa-aa-aaaa",
                "session_id": "asdfasdfs",
                "source_ip": "1.2.2.1",
                "source_port": 1234,
                "start_time": "2024-06-09T23:56:57.51Z",
                "stop_time": "2024-06-09T23:56:58.037Z",
            }
        ]

        response = client.sensor_activity(
            workspace_id=workspace_id, size=5, scroll="scroll"
        )

        assert response == expected_response


class TestQuery(object):
    """GreyNoise client query test cases."""

    def test_query(self, client):
        """Run GNQL query."""
        query = "<query>"
        expected_response = []

        client._request = Mock(return_value=expected_response)
        response = client.query(query)
        client._request.assert_called_with(
            "v3/gnql", params={"query": query, "quick": False}
        )
        assert response == expected_response

    def test_query_with_size_and_scroll(self, client):
        """Run GNQL query with size and scroll parameters."""
        query = "<query>"
        expected_response = []

        client._request = Mock(return_value=expected_response)
        response = client.query(query, size=5, scroll="scroll")
        client._request.assert_called_with(
            "v3/gnql",
            params={"query": query, "quick": False, "size": 5, "scroll": "scroll"},
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
            "v2/experimental/gnql/stats", params={"query": query}
        )
        assert response == expected_response


class TestMeta(object):
    """GreyNoise client run GNQL stats query test cases."""

    def test_metadata(self, client):
        """Run GNQL stats query."""
        expected_response = []

        client._request = Mock(return_value=expected_response)
        response = client.metadata()
        client._request.assert_called_with("v2/meta/metadata")
        assert response == expected_response


class TestPing(object):
    """GreyNoise client run Ping test cases."""

    def test_ping(self, client):
        """Run ping test"""
        expected_response = {"message": "pong"}

        client._request = Mock(return_value=expected_response)
        response = client.test_connection()
        client._request.assert_called_with("ping")
        assert response == expected_response


class TestCVE(object):
    """GreyNoise client CVE lookup test cases."""

    def test_cve(self, client):
        """Get CVE details."""
        cve_id = "CVE-2021-44228"
        expected_response = {}

        client._request = Mock(return_value=expected_response)
        response = client.cve(cve_id)
        client._request.assert_called_with("v1/cve/{}".format(cve_id))
        assert response == expected_response

    def test_invalid_cve(self, client):
        """Get invalid CVE ID information."""
        invalid_cve = "not-a-cve"
        client._request = Mock()

        with pytest.raises(ValueError) as exception:
            client.cve(invalid_cve)
        assert str(exception.value) == f"Invalid CVE ID format: '{invalid_cve}'"
        client._request.assert_not_called()

    def test_community_offering(self, client):
        """Test CVE lookup with community offering."""
        client.offering = "community"
        response = client.cve("CVE-2021-44228")
        assert response == {
            "message": "CVE lookup is not supported with Community offering"
        }


class TestSimilar(object):
    """GreyNoise client Similar context test cases."""

    def test_similar(self, client):
        """Get similar IP addresses."""
        ip_address = "8.8.8.8"
        expected_response = {}

        client._request = Mock(return_value=expected_response)
        response = client.similar(ip_address)
        client._request.assert_called_with(
            "v3/similarity/ips/{}?limit=50".format(ip_address)
        )
        assert response == expected_response

    def test_similar_with_limit_and_score(self, client):
        """Get similar IP addresses with limit and minimum score."""
        ip_address = "8.8.8.8"
        expected_response = {}

        client._request = Mock(return_value=expected_response)
        response = client.similar(ip_address, limit=10, min_score=80)
        client._request.assert_called_with(
            "v3/similarity/ips/{}?limit=10&minimum_score=0.8".format(ip_address)
        )
        assert response == expected_response

    def test_invalid_ip(self, client):
        """Get invalid IP address information."""
        invalid_ip = "not an ip address"
        client._request = Mock()

        with pytest.raises(ValueError) as exception:
            client.similar(invalid_ip)
        assert str(exception.value) == "Invalid IP address: {!r}".format(invalid_ip)

        client._request.assert_not_called()

    def test_community_offering(self, client):
        """Test similar lookup with community offering."""
        client.offering = "community"
        response = client.similar("8.8.8.8")
        assert response == {
            "message": "Similarity lookup not supported with Community offering"
        }


class TestTimeline(object):
    """GreyNoise client Timeline test cases."""

    def test_timeline(self, client):
        """Get IP address timeline."""
        ip_address = "8.8.8.8"
        expected_response = {}

        client._request = Mock(return_value=expected_response)
        response = client.timeline(ip_address)
        client._request.assert_called_with(
            "v3/noise/ips/{}/timeline?field=classification".format(ip_address)
        )
        assert response == expected_response

    def test_invalid_ip(self, client):
        """Get invalid IP address information."""
        invalid_ip = "not an ip address"
        client._request = Mock()

        with pytest.raises(ValueError) as exception:
            client.timeline(invalid_ip)
        assert str(exception.value) == "Invalid IP address: {!r}".format(invalid_ip)

        client._request.assert_not_called()


class TestTimelineHourly(object):
    """GreyNoise client Timeline Hourly test cases."""

    def test_timelinehourly(self, client):
        """Get IP address hourly timeline."""
        ip_address = "8.8.8.8"
        expected_response = {}

        client._request = Mock(return_value=expected_response)
        response = client.timelinehourly(ip_address)
        client._request.assert_called_with(
            "v3/noise/ips/{}/hourly-summary?limit=100".format(ip_address)
        )
        assert response == expected_response

    def test_invalid_ip(self, client):
        """Get invalid IP address information."""
        invalid_ip = "not an ip address"
        client._request = Mock()

        with pytest.raises(ValueError) as exception:
            client.timelinehourly(invalid_ip)
        assert str(exception.value) == "Invalid IP address: {!r}".format(invalid_ip)

        client._request.assert_not_called()


def test_api_config():
    """Test API configuration initialization."""
    config = APIConfig(
        api_key="test-api-key",
        api_server="https://api.greynoise.io",
        timeout=30,
        proxy="http://proxy.example.com",
        offering="enterprise",
        integration_name="test",
        cache_max_size=2000000,
        cache_ttl=7200,
        use_cache=True,
    )
    assert config.api_key == "test-api-key"
    assert config.api_server == "https://api.greynoise.io"
    assert config.timeout == 30
    assert config.proxy == "http://proxy.example.com"
    assert config.offering == "enterprise"
    assert config.integration_name == "test"
    assert config.cache_max_size == 2000000
    assert config.cache_ttl == 7200
    assert config.use_cache is True


def test_api_client_initialization():
    """Test API client initialization with configuration."""
    config = APIConfig(
        api_key="test-api-key",
        api_server="https://api.greynoise.io",
        timeout=30,
        proxy="http://proxy.example.com",
        offering="enterprise",
        integration_name="test",
        cache_max_size=2000000,
        cache_ttl=7200,
        use_cache=True,
    )
    client = GreyNoise(config)
    assert client.config == config
    assert client.session is not None
    assert client._executor is not None
    assert client.ip_quick_check_cache is not None
    assert client.ip_context_cache is not None


def test_api_client_request_retry():
    """Test API client request retry functionality."""
    config = APIConfig(
        api_key="test-api-key",
        api_server="https://api.greynoise.io",
        timeout=30,
        proxy="http://proxy.example.com",
        offering="enterprise",
        integration_name="test",
        use_cache=True,
    )
    client = GreyNoise(config)

    # Create mock responses with proper structure
    mock_response1 = Mock()
    mock_response1.status_code = 500
    mock_response1.headers = Mock()
    mock_response1.headers.get = Mock(return_value="application/json")
    mock_response1.text = '{"error": "Internal Server Error"}'
    mock_response1.json = Mock(return_value={"error": "Internal Server Error"})

    mock_response2 = Mock()
    mock_response2.status_code = 502
    mock_response2.headers = Mock()
    mock_response2.headers.get = Mock(return_value="application/json")
    mock_response2.text = '{"error": "Bad Gateway"}'
    mock_response2.json = Mock(return_value={"error": "Bad Gateway"})

    mock_response3 = Mock()
    mock_response3.status_code = 200
    mock_response3.headers = Mock()
    mock_response3.headers.get = Mock(return_value="application/json")
    mock_response3.text = '{"success": true}'
    mock_response3.json = Mock(return_value={"success": True})

    with patch.object(client.session, "get") as mock_get:
        # Set up the side effect to return our mock responses in sequence
        mock_get.side_effect = [mock_response1, mock_response2, mock_response3]

        # The first two calls should raise RequestFailure
        with pytest.raises(RequestFailure) as exc_info:
            client._request("test-endpoint")
        assert exc_info.value.args[0] == 500
        assert exc_info.value.args[1] == mock_response1.json.return_value

        with pytest.raises(RequestFailure) as exc_info:
            client._request("test-endpoint")
        assert exc_info.value.args[0] == 502
        assert exc_info.value.args[1] == mock_response2.json.return_value

        # The third call should succeed
        response = client._request("test-endpoint")
        assert response == mock_response3.json.return_value
        assert mock_get.call_count == 3


def test_api_client_parallel_processing():
    """Test API client parallel processing functionality."""
    config = APIConfig(
        api_key="test-api-key",
        api_server="https://api.greynoise.io",
        timeout=30,
        proxy="http://proxy.example.com",
        offering="enterprise",
        integration_name="test",
        use_cache=True,
    )
    client = GreyNoise(config)

    def process_func(items):
        return {"data": [{"processed": item} for item in items]}

    items = list(range(100))
    results = client._process_batch_parallel(
        items, process_func, batch_size=10, max_workers=5
    )

    assert isinstance(results, dict)
    assert "data" in results
    assert len(results["data"]) == 100
    assert all(
        isinstance(result, dict) and "processed" in result for result in results["data"]
    )
