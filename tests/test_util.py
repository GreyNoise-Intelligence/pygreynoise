import pytest

from greynoise.util import validate_date


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
