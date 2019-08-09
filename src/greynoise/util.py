"""Utility functions."""

import logging
import os
import socket

import appdirs

from six.moves.configparser import ConfigParser


LOGGER = logging.getLogger(__name__)


def load_config():
    """Load configuration."""
    defaults = {'api_key': 'api key not provided'}
    if 'GREYNOISE_API_KEY' in os.environ:
        api_key = os.environ['GREYNOISE_API_KEY']
        LOGGER.debug('API key found in environment variable: %s', api_key)
        defaults['api_key'] = api_key
    config_parser = ConfigParser(defaults)

    config_file = os.path.join(appdirs.user_config_dir(), 'greynoise', 'config')
    if os.path.isfile(config_file):
        LOGGER.debug('Parsing configuration file: %s...', config_file)
        config_parser.read(config_file)
        if 'greynoise' not in config_parser:
            raise ValueError(
                'greynoise section not found in configuration file: {}'
                .format(config_file)
            )
    else:
        LOGGER.debug('Configuration file not found: %s', config_file)

    return {
        'api_key': config_parser.get('greynoise', 'api_key')
    }


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
