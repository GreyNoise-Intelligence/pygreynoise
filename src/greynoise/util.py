"""Utility functions."""

import logging
import os
import socket

from six.moves.configparser import ConfigParser

CONFIG_FILE = os.path.expanduser(os.path.join("~", ".config", "greynoise", "config"))
LOGGER = logging.getLogger(__name__)

DEFAULT_CONFIG = {"api_key": "", "timeout": 60}


def load_config():
    """Load configuration.

    :returns:
        Current configuration based on configuration file and environment variables.
    :rtype: dict

    """
    config_parser = ConfigParser(
        {key: str(value) for key, value in DEFAULT_CONFIG.items()}
    )
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

    if "GREYNOISE_TIMEOUT" in os.environ:
        timeout = os.environ["GREYNOISE_TIMEOUT"]
        try:
            int(timeout)
        except ValueError:
            LOGGER.error(
                "GREYNOISE_TIMEOUT environment variable "
                "cannot be converted to an integer: %r",
                timeout,
            )
        else:
            LOGGER.debug("Timeout found in environment variable: %s", timeout)
            # Environment variable takes precedence over configuration file content
            config_parser.set("greynoise", "timeout", timeout)

    return {
        "api_key": config_parser.get("greynoise", "api_key"),
        "timeout": config_parser.getint("greynoise", "timeout"),
    }


def save_config(config):
    """Save configuration.

    :param config: Data to be written to the configuration file.
    :type config:  dict

    """
    config_parser = ConfigParser()
    config_parser.add_section("greynoise")
    config_parser.set("greynoise", "api_key", config["api_key"])
    config_parser.set("greynoise", "timeout", str(config["timeout"]))

    config_dir = os.path.dirname(CONFIG_FILE)
    if not os.path.isdir(config_dir):
        os.makedirs(config_dir)

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
        error_message = "Invalid IP address: {!r}".format(ip_address)
        LOGGER.warning(error_message)
        if strict:
            raise ValueError(error_message)
        return False
