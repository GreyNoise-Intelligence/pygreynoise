import datetime
import socket


def valid_date(date):
    """Check the input date and ensure it matches the format."""
    try:
        datetime.datetime.strptime(date, "%Y-%m-%d")
    except ValueError:
        raise ValueError("Incorrect data format, should be YYYY-MM-DD")


def valid_ip(ip_address, strict=True):
    """Check if the IP address is valid."""
    try:
        socket.inet_aton(ip_address)
        return True
    except socket.error:
        if strict:
            raise ValueError("Invalid IP address")
        return False
