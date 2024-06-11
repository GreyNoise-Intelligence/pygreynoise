"""GreyNoise API client test cases."""

import pytest
from mock import Mock, call, patch

from greynoise.__version__ import __version__
from greynoise.api import GreyNoise
from greynoise.exceptions import RateLimitError, RequestFailure


@pytest.fixture
def client():
    """API client fixture."""
    client = GreyNoise(api_key="<api_key>", integration_name="test")
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
        config = {
            "api_key": "<api_key>",
            "api_server": "<api_server>",
            "timeout": "<timeout>",
            "proxy": "<proxy>",
            "offering": "<offering>",
        }
        with patch("greynoise.api.load_config") as load_config:
            client = GreyNoise(**config)
            assert client.api_key == config["api_key"]
            assert client.api_server == config["api_server"]
            assert client.timeout == config["timeout"]
            assert client.proxy == config["proxy"]
            assert client.offering == config["offering"]
            load_config.assert_not_called()

    def test_without_api_key(self):
        """API parameter is not passed."""
        config = {
            "api_key": "<api_key>",
            "api_server": "<api_server>",
            "timeout": "<timeout>",
            "proxy": "<proxy>",
            "offering": "<offering>",
        }
        with patch("greynoise.api.load_config") as load_config:
            load_config.return_value = config
            client = GreyNoise()
            assert client.api_key == config["api_key"]
            assert client.api_server == config["api_server"]
            assert client.timeout == config["timeout"]
            assert client.proxy == config["proxy"]
            assert client.offering == config["offering"]
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

    def test_request_method_parameters(self, client):
        """Request method is called with expected parameters."""
        expected_response = {"expected": "response"}
        client.session = Mock()
        response = client.session.get()
        response.status_code = 200
        response.headers.get.return_value = "application/json"
        response.json.return_value = expected_response

        response = client._request("endpoint")
        assert response == expected_response
        client.session.get.assert_called_with(
            "{}/{}".format(client.api_server, "endpoint"),
            headers={
                "User-Agent": "GreyNoise/{} (test)".format(__version__),
                "key": "<api_key>",
            },
            timeout=client.timeout,
            params={},
            json=None,
            files=None,
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


class TestInteresting(object):
    """GreyNoise client "interesting" IP test cases."""

    def test_interesting(self, client):
        """Report an IP as "interesting"."""
        ip_address = "8.8.8.8"
        expected_response = {}
        client._request = Mock(return_value=expected_response)
        response = client.interesting(ip_address)
        client._request.assert_called_with(
            "v2/interesting/{}".format(ip_address), method="post"
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
        ip_address = "8.8.8.8"
        expected_response = {}

        client._request = Mock(return_value=expected_response)
        response = client.ip(ip_address)
        client._request.assert_called_with("v2/noise/context/{}".format(ip_address))
        assert response == expected_response

    def test_ip_with_cache(self, client):
        """Get IP address information with cache."""
        ip_address = "8.8.8.8"
        expected_response = {}

        client._request = Mock(return_value=expected_response)
        client.ip(ip_address)
        client._request.assert_called_with("v2/noise/context/{}".format(ip_address))

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
        client._request.assert_called_with("v2/noise/context/{}".format(ip_address))

        client._request.reset_mock()
        client.ip(ip_address)
        client._request.assert_called_with("v2/noise/context/{}".format(ip_address))

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
                ["8.8.8.8", "67.68.68.79", "123.123.123.123"],
                call(
                    "v2/noise/multi/quick",
                    method="post",
                    json={"ips": ["8.8.8.8", "67.68.68.79", "123.123.123.123"]},
                ),
                [
                    {"code": "0x00", "ip": "8.8.8.8", "noise": False},
                    {"code": "0x01", "ip": "67.68.68.79", "noise": False},
                    {"code": "0x99", "ip": "123.123.123.123", "noise": False},
                ],
                [
                    {
                        "code": "0x00",
                        "code_message": (
                            "IP has never been observed scanning the Internet"
                        ),
                        "ip": "8.8.8.8",
                        "noise": False,
                    },
                    {
                        "code": "0x01",
                        "code_message": (
                            "IP has been observed by the GreyNoise sensor network"
                        ),
                        "ip": "67.68.68.79",
                        "noise": False,
                    },
                    {
                        "code": "0x99",
                        "code_message": "Code message unknown: 0x99",
                        "ip": "123.123.123.123",
                        "noise": False,
                    },
                ],
            ),
            (
                ["8.8.8.8", "not-an-ip", "123.123.123.123"],
                call(
                    "v2/noise/multi/quick",
                    method="post",
                    json={"ips": ["8.8.8.8", "123.123.123.123"]},
                ),
                [
                    {"code": "0x00", "ip": "8.8.8.8", "noise": False},
                    {"code": "0x99", "ip": "123.123.123.123", "noise": False},
                ],
                [
                    {
                        "code": "0x00",
                        "code_message": (
                            "IP has never been observed scanning the Internet"
                        ),
                        "ip": "8.8.8.8",
                        "noise": False,
                    },
                    {
                        "code": "0x99",
                        "code_message": "Code message unknown: 0x99",
                        "ip": "123.123.123.123",
                        "noise": False,
                    },
                ],
            ),
            (
                "8.8.8.8",
                call("v2/noise/multi/quick", method="post", json={"ips": ["8.8.8.8"]}),
                {"code": "0x00", "ip": "8.8.8.8", "noise": False},
                [
                    {
                        "code": "0x00",
                        "code_message": (
                            "IP has never been observed scanning the Internet"
                        ),
                        "ip": "8.8.8.8",
                        "noise": False,
                    }
                ],
            ),
            (
                ["not-an-ip#1", "8.8.8.8", "not-an-ip#2"],
                call("v2/noise/multi/quick", method="post", json={"ips": ["8.8.8.8"]}),
                {"code": "0x00", "ip": "8.8.8.8", "noise": False},
                [
                    {
                        "code": "0x00",
                        "code_message": (
                            "IP has never been observed scanning the Internet"
                        ),
                        "ip": "8.8.8.8",
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
                ["8.8.8.8", "67.68.68.79", "123.123.123.123"],
                call(
                    "v2/noise/multi/quick",
                    method="post",
                    json={"ips": ["8.8.8.8", "67.68.68.79", "123.123.123.123"]},
                ),
                [
                    {"code": "0x00", "ip": "8.8.8.8", "noise": False},
                    {"code": "0x01", "ip": "67.68.68.79", "noise": False},
                    {"code": "0x99", "ip": "123.123.123.123", "noise": False},
                ],
            ),
            (
                ["8.8.8.8", "not-an-ip", "123.123.123.123"],
                call(
                    "v2/noise/multi/quick",
                    method="post",
                    json={"ips": ["8.8.8.8", "123.123.123.123"]},
                ),
                [
                    {"code": "0x00", "ip": "8.8.8.8", "noise": False},
                    {"code": "0x99", "ip": "123.123.123.123", "noise": False},
                ],
            ),
            (
                "8.8.8.8",
                call("v2/noise/multi/quick", method="post", json={"ips": ["8.8.8.8"]}),
                {"code": "0x00", "ip": "8.8.8.8", "noise": False},
            ),
            (
                ["not-an-ip#1", "8.8.8.8", "not-an-ip#2"],
                call("v2/noise/multi/quick", method="post", json={"ips": ["8.8.8.8"]}),
                {"code": "0x00", "ip": "8.8.8.8", "noise": False},
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
                ["8.8.8.8", "67.68.68.79", "123.123.123.123"],
                call(
                    "v2/noise/multi/quick",
                    method="post",
                    json={"ips": ["8.8.8.8", "67.68.68.79", "123.123.123.123"]},
                ),
                [
                    {"code": "0x00", "ip": "8.8.8.8", "noise": False},
                    {"code": "0x01", "ip": "67.68.68.79", "noise": False},
                    {"code": "0x99", "ip": "123.123.123.123", "noise": False},
                ],
            ),
            (
                ["8.8.8.8", "not-an-ip", "123.123.123.123"],
                call(
                    "v2/noise/multi/quick",
                    method="post",
                    json={"ips": ["8.8.8.8", "123.123.123.123"]},
                ),
                [
                    {"code": "0x00", "ip": "8.8.8.8", "noise": False},
                    {"code": "0x99", "ip": "123.123.123.123", "noise": False},
                ],
            ),
            (
                "8.8.8.8",
                call("v2/noise/multi/quick", method="post", json={"ips": ["8.8.8.8"]}),
                {"code": "0x00", "ip": "8.8.8.8", "noise": False},
            ),
            (
                ["not-an-ip#1", "8.8.8.8", "not-an-ip#2"],
                call("v2/noise/multi/quick", method="post", json={"ips": ["8.8.8.8"]}),
                {"code": "0x00", "ip": "8.8.8.8", "noise": False},
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
    """GreyNoise client run GNQL query test cases."""

    def test_query(self, client):
        """Run GNQL query."""
        query = "<query>"
        expected_response = []

        client._request = Mock(return_value=expected_response)
        response = client.query(query)
        client._request.assert_called_with(
            "v2/experimental/gnql", params={"query": query}
        )
        assert response == expected_response

    def test_query_with_size_and_scroll(self, client):
        """Run GNQL query with size and scroll parameters."""
        query = "<query>"
        expected_response = []

        client._request = Mock(return_value=expected_response)
        response = client.query(query, size=5, scroll="scroll")
        client._request.assert_called_with(
            "v2/experimental/gnql",
            params={"query": query, "size": 5, "scroll": "scroll"},
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


class TestSimilar(object):
    """GreyNoise client Similar context test cases."""

    def test_similar(self, client):
        """Get IP address information."""
        ip_address = "8.8.8.8"
        expected_response = {}

        client._request = Mock(return_value=expected_response)
        response = client.similar(ip_address)
        client._request.assert_called_with(
            "v3/similarity/ips/{}?limit=50".format(ip_address)
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


class TestTimeline(object):
    """GreyNoise client Similar context test cases."""

    def test_timeline(self, client):
        """Get IP address information."""
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
    """GreyNoise client Similar context test cases."""

    def test_timelinehourly(self, client):
        """Get IP address information."""
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
