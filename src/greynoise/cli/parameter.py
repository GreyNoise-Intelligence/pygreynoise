"""Command line parameter types."""

import click

from greynoise.util import validate_ip


def ip_addresses_parameter(_context, _parameter, values):
    """IPv4 addresses passed from the command line.

    :param values: IPv4 address values
    :type value: list
    :raises click.BadParameter: when any IP address value is invalid

    """
    for value in values:
        try:
            validate_ip(value)
        except ValueError:
            raise click.BadParameter(value)

    return values
