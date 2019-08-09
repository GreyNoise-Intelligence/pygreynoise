"""Utility functions."""

import socket


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
