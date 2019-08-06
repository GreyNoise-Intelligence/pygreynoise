import pytest

from greynoise.util import (
    validate_date,
    validate_ip,
)


class TestValidateDate(object):

    """Date validation test cases."""

    @pytest.mark.parametrize(
        'date',
        (
            '2019-01-01',
            '2019-1-01',
            '2019-01-1',
        ),
    )
    def test_valid(self, date):
        """Valid date values."""
        validate_date(date)

    @pytest.mark.parametrize(
        'date',
        (
            '19-01-01',
            'not a date',
        ),
    )
    def test_invalid(self, date):
        """Invalid date values."""
        with pytest.raises(ValueError):
            validate_date(date)


class TestValidateIP(object):

    """IP validation test cases."""

    @pytest.mark.parametrize(
        'ip',
        (
            '0.0.0.0',
            '255.255.255.255',
            '192.168.1.0',
        ),
    )
    def test_valid(self, ip):
        """Valid ip address values."""
        validate_ip(ip)

    @pytest.mark.parametrize(
        'ip',
        (
            '0.0.0.-1',
            '255.255.255.256',
            'not an ip address',
        ),
    )
    def test_invalid(self, ip):
        """Invalid ip address values."""
