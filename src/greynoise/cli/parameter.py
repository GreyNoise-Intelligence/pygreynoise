"""Command line parameter types."""

from argparse import ArgumentTypeError
from datetime import datetime

from greynoise.util import validate_ip


def ip_address_parameter(ip_address):
    """IPv4 parameter passed from the command line.

    :param ip_address: IPv4 address value
    :type ip_address: str
    :raises argparse.ArgumentTypeError: if ip_address value is invalid

    """
    try:
        validate_ip(ip_address)
    except ValueError as exception:
        raise ArgumentTypeError(str(exception))

    return ip_address


def date_parameter(date):
    """Date parameter passed from the command line.

    :param date: Date value
    :type date: str
    :raises argparse.ArgumentTypeError: if date value is invalid

    """
    try:
        return datetime.strptime(date, "%Y-%m-%d").date()
    except ValueError:
        raise ArgumentTypeError(
            "Invalid date: {!r}. Expected format: YYYY-MM-DD".format(date)
        )
