import pytest

from mock import Mock

from greynoise.client import GreyNoise


@pytest.fixture
def client():
    client = GreyNoise('<api_key>')
    yield client


class TestGetContext(object):
    """GreyNoise client IP context test cases."""

    def test_get_context(self, client):
        """Get IP address information."""
        ip_address = '0.0.0.0'
        expected_response = {}

        client._request = Mock(return_value=expected_response)
        response = client.get_context(ip_address)
        client._request.assert_called_with('noise/context/{}'.format(ip_address))
        assert response == expected_response

    def test_get_context_invalid_ip(self, client):
        """Get invalid IP address information."""
        client._request = Mock()

        with pytest.raises(ValueError):
            client.get_context('not an ip address')

        client._request.assert_not_called()
