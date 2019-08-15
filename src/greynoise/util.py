"""Utility functions."""

import logging
import os
import socket

import appdirs

from six.moves.configparser import ConfigParser


CONFIG_FILE = os.path.join(appdirs.user_config_dir(), "greynoise", "config")
LOGGER = logging.getLogger(__name__)


def load_config():
    """Load configuration.

    :returns:
        Current configuration based on configuration file and environment variables.
    :rtype: dict

    """
    defaults = {"api_key": ""}
    config_parser = ConfigParser(defaults)
    config_parser.add_section("greynoise")

    if os.path.isfile(CONFIG_FILE):
        LOGGER.debug("Parsing configuration file: %s...", CONFIG_FILE)
        with open(CONFIG_FILE) as config_file:
            config_parser.readfp(config_file)
    else:
        LOGGER.debug("Configuration file not found: %s", CONFIG_FILE)

    if "GREYNOISE_API_KEY" in os.environ:
        api_key = os.environ["GREYNOISE_API_KEY"]
        LOGGER.debug("API key found in environment variable: %s", api_key)

        # Environment variable takes precedence over configuration file content
        config_parser.set("greynoise", "api_key", api_key)

    return {"api_key": config_parser.get("greynoise", "api_key")}


def save_config(config):
    """Save configuration.

    :param config: Data to be written to the configuration file.
    :type config:  dict

    """
    config_parser = ConfigParser()
    config_parser.add_section("greynoise")
    config_parser.set("greynoise", "api_key", config["api_key"])

    config_dir = os.path.dirname(CONFIG_FILE)
    if not os.path.isdir(config_dir):
        os.makedirs(os.path.dirname(CONFIG_FILE))

    with open(CONFIG_FILE, "w") as config_file:
        config_parser.write(config_file)


def validate_ip(ip_address, strict=True):
    """Check if the IPv4 address is valid.

    :param ip_address: IPv4 address value to validate.
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
            raise ValueError("Invalid IP address: {!r}".format(ip_address))
        return False
