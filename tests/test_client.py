import pytest

from mock import Mock

from greynoise.client import GreyNoise
from greynoise.exceptions import RequestFailure


@pytest.fixture
def client():
    """API client fixture."""
    client = GreyNoise(api_key="<api_key>")
    yield client


class TestRequest(object):
    """GreyNoise client _request method test cases."""

    @pytest.mark.parametrize(
        'status_code',
        (100, 300, 400, 500),
    )
    def test_status_code_failure(self, client, status_code):
        """Exception is raised on response status code failure."""
        client.session = Mock()
        client.session.get().status_code = status_code
        with pytest.raises(RequestFailure):
            client._request('endpoint')

    def test_json(self, client):
        """Response's json payload is returned."""
        expected_response = {'expected': 'response'}
        client.session = Mock()
        client.session.get().status_code = 200
        client.session.get().json.return_value = expected_response

        response = client._request('endpoint')
        assert response == expected_response


class TestGetContext(object):
    """GreyNoise client IP context test cases."""

    def test_get_context(self, client):
        """Get IP address information."""
        ip_address = '0.0.0.0'
        expected_response = {}

        client._request = Mock(return_value=expected_response)
        response = client.get_context(ip_address)
        client._request.assert_called_with("noise/context/{}".format(ip_address))
        assert response == expected_response

    def test_get_context_invalid_ip(self, client):
        """Get invalid IP address information."""
        client._request = Mock()

        with pytest.raises(ValueError) as exception:
            client.get_context("not an ip address")
        assert str(exception.value) == "Invalid IP address"

        client._request.assert_not_called()


class TestGetNoiseStatus(object):
    """GreyNoise client IP quick check test cases."""

    @pytest.mark.parametrize(
        'ip_address, mock_response, expected_results',
        (
            (
                "0.0.0.0",
                {
                    "code": "0x00",
                    "ip_address": "0.0.0.0",
                    "noise": False,
                },
                {
                    "code": "0x00",
                    "code_message": "IP has never been observed scanning the Internet",
                    "ip_address": "0.0.0.0",
                    "noise": False,
                },
            ),
            (
                "127.0.0.1",
                {
                    "code": "0x01",
                    "ip_address": "127.0.0.1",
                    "noise": False,
                },
                {
                    "code": "0x01",
                    "code_message": (
                        "IP has been observed by the GreyNoise sensor network"
                    ),
                    "ip_address": "127.0.0.1",
                    "noise": False,
                },
            ),
            (
                "10.0.0.0",
                {
                    "code": "0x99",
                    "ip_address": "10.0.0.0",
                    "noise": True,
                },
                {
                    "code": "0x99",
                    "code_message": "Code message unknown: 0x99",
                    "ip_address": "10.0.0.0",
                    "noise": True,
                },
            ),
        ),
    )
    def test_get_noise_status(
            self, client, ip_address, mock_response, expected_results,
    ):
        """Get IP address noise status."""
        client._request = Mock(return_value=mock_response)
        response = client.get_noise_status(ip_address)
        client._request.assert_called_with('noise/quick/{}'.format(ip_address))
        assert response == expected_results

    def test_get_noise_status_invalid_ip(self, client):
        """Get invalid IP address noise status."""
        client._request = Mock()

        with pytest.raises(ValueError) as exception:
            client.get_noise_status('not an ip address')
        assert str(exception.value) == 'Invalid IP address'

        client._request.assert_not_called()


class TestGetNoiseStatusBulk(object):
    """GreyNoise client IP multi quick check test cases."""

    @pytest.mark.parametrize(
        'ip_addresses, filtered_ip_addresses, mock_response, expected_results',
        (
            (
                ["0.0.0.0", "127.0.0.1", "10.0.0.0"],
                ["0.0.0.0", "127.0.0.1", "10.0.0.0"],
                [
                    {
                        "code": "0x00",
                        "ip_address": "0.0.0.0",
                        "noise": False,
                    },
                    {
                        "code": "0x01",
                        "ip_address": "127.0.0.1",
                        "noise": False,
                    },
                    {
                        "code": "0x99",
                        "ip_address": "10.0.0.0",
                        "noise": False,
                    },
                ],
                [
                    {
                        "code": "0x00",
                        "code_message": (
                            "IP has never been observed scanning the Internet"
                        ),
                        "ip_address": "0.0.0.0",
                        "noise": False,
                    },
                    {
                        "code": "0x01",
                        "code_message": (
                            "IP has been observed by the GreyNoise sensor network"
                        ),
                        "ip_address": "127.0.0.1",
                        "noise": False,
                    },
                    {
                        "code": "0x99",
                        "code_message": "Code message unknown: 0x99",
                        "ip_address": "10.0.0.0",
                        "noise": False,
                    },
                ]
            ),
            (
                ["not-an-ip#1", "0.0.0.0", "not-an-ip#2"],
                ["0.0.0.0"],
                [
                    {
                        "code": "0x00",
                        "ip_address": "0.0.0.0",
                        "noise": False,
                    },
                ],
                [
                    {
                        "code": "0x00",
                        "code_message": (
                            "IP has never been observed scanning the Internet"
                        ),
                        "ip_address": "0.0.0.0",
                        "noise": False,
                    },
                ],
            ),
        ),
    )
    def test_get_noise_status_bulk(
        self, client, ip_addresses, filtered_ip_addresses, mock_response,
        expected_results,
    ):
        """Get IP address noise status."""
        client._request = Mock(return_value=mock_response)
        results = client.get_noise_status_bulk(ip_addresses)
        client._request.assert_called_with(
            'noise/multi/quick',
            json={'ips': filtered_ip_addresses},
        )
        assert results == expected_results

    def test_get_noise_status_bulk_not_a_list(self, client):
        """ValueError raised when argument is not a list."""
        with pytest.raises(ValueError) as exception:
            client.get_noise_status_bulk("not a list")
        assert str(exception.value) == "`ip_addresses` must be a list"


class TestGetNoise(object):
    """GreyNoise client bulk test cases."""

    @pytest.mark.parametrize(
        'date, api_responses, expected_noise_ips',
        (
            (
                None,
                [{'complete': True}],
                [],
            ),
            (
                '2019-01-01',
                [
                    {
                        'noise_ips': ['0.0.0.0'],
                        'offset': 1,
                        'complete': False,
                    },
                    {'complete': True},
                ],
                ['0.0.0.0'],
            ),
        ),
    )
    def test_get_noise(self, client, date, api_responses, expected_noise_ips):
        """Get noise IPs."""
        client._request = Mock(side_effect=api_responses)
        noise_ips = client.get_noise(date)
        assert noise_ips == expected_noise_ips
