"""Utility functions."""

import datetime
import socket


def validate_date(date):
    """Check the input date and ensure it matches the format.

    :param date: Date value to validate.
    :type date: str
    :raises ValueError: When validation fails.

    """
    try:
        datetime.datetime.strptime(date, "%Y-%m-%d")
    except ValueError:
        raise ValueError("Incorrect data format, should be YYYY-MM-DD")


def validate_ip(ip_address, strict=True):
    """Check if the IP address is valid.

    :param ip_address: IP address value to validate.
    :type ip_address: str
    :param strict: Whether to raise exception if validation fails.
    :type strict: bool
    :raises ValueError: When validation fails and strict is set to True.

    """
    try:
        socket.inet_aton(ip_address)
        return True
    except socket.error:
        if strict:
            raise ValueError("Invalid IP address")
        return False
