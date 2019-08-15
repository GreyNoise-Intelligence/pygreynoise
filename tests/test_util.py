"""Utility functions test cases."""

import pytest

from greynoise.util import validate_ip


class TestValidateIP(object):

    """IP validation test cases."""

    @pytest.mark.parametrize(
        "ip",
        (
            "0.0.0.0",
            "255.255.255.255",
            "192.168.1.0",
        ),
    )
    def test_valid(self, ip):
        """Valid ip address values."""
        validate_ip(ip)

    @pytest.mark.parametrize(
        "ip",
        (
            "0.0.0.-1",
            "255.255.255.256",
            "not an ip address",
        ),
    )
    def test_invalid(self, ip):
        """Invalid ip address values."""
        with pytest.raises(ValueError) as exception:
            validate_ip(ip)
        assert str(exception.value) == "Invalid IP address"
