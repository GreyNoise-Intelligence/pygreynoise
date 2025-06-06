"""Utility functions."""

import configparser
import logging
import os
import re
from importlib import resources
from ipaddress import IPv6Address, ip_address

CONFIG_FILE = os.path.expanduser(os.path.join("~", ".config", "greynoise", "config"))
LOGGER = logging.getLogger(__name__)

DEFAULT_CONFIG = {
    "api_key": "",
    "api_server": "https://api.greynoise.io",
    "timeout": 60,
    "proxy": "",
    "offering": "enterprise",
    "cache_max_size": 1000000,
    "cache_ttl": 3600,
    "use_cache": True,
}


def load_config():
    """Load configuration.

    :returns:
        Current configuration based on configuration file and environment variables.
    :rtype: dict

    """
    config_parser = configparser.ConfigParser(
        {key: str(value) for key, value in DEFAULT_CONFIG.items()}
    )
    config_parser.add_section("greynoise")

    if os.path.isfile(CONFIG_FILE):
        LOGGER.debug("Parsing configuration file: %s...", CONFIG_FILE)
        with open(CONFIG_FILE) as config_file:
            config_parser.read_file(config_file)
    else:
        LOGGER.debug("Configuration file not found: %s", CONFIG_FILE)

    if "GREYNOISE_API_KEY" in os.environ:
        api_key = os.environ["GREYNOISE_API_KEY"]
        LOGGER.debug("API key found in environment variable: %s", api_key)
        # Environment variable takes precedence over configuration file content
        config_parser.set("greynoise", "api_key", api_key)

    if "GREYNOISE_API_SERVER" in os.environ:
        api_server = os.environ["GREYNOISE_API_SERVER"]
        LOGGER.debug("API server found in environment variable: %s", api_server)
        # Environment variable takes precedence over configuration file content
        config_parser.set("greynoise", "api_server", api_server)

    if "GREYNOISE_TIMEOUT" in os.environ:
        timeout = os.environ["GREYNOISE_TIMEOUT"]
        try:
            int(timeout)
        except ValueError:
            timeout = DEFAULT_CONFIG["timeout"]
        # Environment variable takes precedence over configuration file content
        config_parser.set("greynoise", "timeout", str(timeout))

    if "GREYNOISE_PROXY" in os.environ:
        proxy = os.environ["GREYNOISE_PROXY"]
        LOGGER.debug("Proxy found in environment variable: %s", proxy)
        # Environment variable takes precedence over configuration file content
        config_parser.set("greynoise", "proxy", proxy)

    if "GREYNOISE_OFFERING" in os.environ:
        offering = os.environ["GREYNOISE_OFFERING"]
        LOGGER.debug("Offering found in environment variable: %s", offering)
        # Environment variable takes precedence over configuration file content
        config_parser.set("greynoise", "offering", offering)

    if "GREYNOISE_CACHE_MAX_SIZE" in os.environ:
        cache_max_size = os.environ["GREYNOISE_CACHE_MAX_SIZE"]
        try:
            int(cache_max_size)
        except ValueError:
            cache_max_size = DEFAULT_CONFIG["cache_max_size"]
        config_parser.set("greynoise", "cache_max_size", str(cache_max_size))

    if "GREYNOISE_CACHE_TTL" in os.environ:
        cache_ttl = os.environ["GREYNOISE_CACHE_TTL"]
        try:
            int(cache_ttl)
        except ValueError:
            cache_ttl = DEFAULT_CONFIG["cache_ttl"]
        config_parser.set("greynoise", "cache_ttl", str(cache_ttl))

    # validate config
    if config_parser.get("greynoise", "timeout"):
        try:
            int(config_parser.get("greynoise", "timeout"))
        except ValueError:
            config_parser.set("greynoise", "timeout", str(DEFAULT_CONFIG["timeout"]))
    if config_parser.get("greynoise", "cache_max_size"):
        try:
            int(config_parser.get("greynoise", "cache_max_size"))
        except ValueError:
            config_parser.set(
                "greynoise", "cache_max_size", str(DEFAULT_CONFIG["cache_max_size"])
            )
    if config_parser.get("greynoise", "cache_ttl"):
        try:
            int(config_parser.get("greynoise", "cache_ttl"))
        except ValueError:
            config_parser.set(
                "greynoise", "cache_ttl", str(DEFAULT_CONFIG["cache_ttl"])
            )

    return {
        "api_key": config_parser.get("greynoise", "api_key"),
        "api_server": config_parser.get("greynoise", "api_server"),
        "timeout": config_parser.getint("greynoise", "timeout"),
        "proxy": config_parser.get("greynoise", "proxy"),
        "offering": config_parser.get("greynoise", "offering"),
        "cache_max_size": config_parser.getint("greynoise", "cache_max_size"),
        "cache_ttl": config_parser.getint("greynoise", "cache_ttl"),
        "use_cache": config_parser.getboolean("greynoise", "use_cache"),
    }


def save_config(config):
    """Save configuration.

    :param config: Data to be written to the configuration file.
    :type config:  dict

    """
    config_parser = configparser.ConfigParser()
    config_parser.add_section("greynoise")

    # Only set values that are provided in the config
    if "api_key" in config:
        config_parser.set("greynoise", "api_key", config["api_key"])
    if "api_server" in config:
        config_parser.set("greynoise", "api_server", config["api_server"])
    if "timeout" in config:
        config_parser.set("greynoise", "timeout", str(config["timeout"]))
    if "proxy" in config:
        config_parser.set("greynoise", "proxy", config["proxy"])
    if "offering" in config:
        config_parser.set("greynoise", "offering", config["offering"])
    if "cache_max_size" in config:
        config_parser.set("greynoise", "cache_max_size", str(config["cache_max_size"]))
    if "cache_ttl" in config:
        config_parser.set("greynoise", "cache_ttl", str(config["cache_ttl"]))
    if "use_cache" in config:
        config_parser.set("greynoise", "use_cache", str(config["use_cache"]))

    config_dir = os.path.dirname(CONFIG_FILE)
    if not os.path.isdir(config_dir):
        os.makedirs(config_dir)

    # If file doesn't exist, create it with default values
    if not os.path.isfile(CONFIG_FILE):
        for key, value in DEFAULT_CONFIG.items():
            if not config_parser.has_option("greynoise", key):
                config_parser.set("greynoise", key, str(value))

    with open(CONFIG_FILE, "w") as config_file:
        config_parser.write(config_file)


def validate_ip(ip, strict=True, print_warning=True):
    """Check if the IPv4 address is valid.

    :param ip_address: IPv4 address value to validate.
    :type ip_address: str
    :param strict: Whether to raise exception if validation fails.
    :type strict: bool
    :raises ValueError: When validation fails and strict is set to True.
    :type print_warning: bool
    :raises ValueError: By default, otherwise returns nothing

    """
    is_valid = False
    error_message = ""

    try:
        ip_address(ip)
        is_valid = True
    except ValueError:
        if print_warning:
            error_message = "Invalid IP address: {!r}".format(ip)
            LOGGER.warning(error_message)
        if strict:
            raise ValueError(error_message)
        return False

    if is_valid:
        if type(ip_address(ip)) is IPv6Address:
            error_message = "IPv6 addresses are not supported: {!r}".format(ip)
            if print_warning:
                LOGGER.warning(error_message)
            if strict:
                raise ValueError(error_message)
            return False
        else:
            is_routable = ip_address(ip).is_global
            if is_routable:
                return True
            else:
                error_message = "Non-Routable IP address: {!r}".format(ip)
                if print_warning:
                    LOGGER.warning(error_message)
                if strict:
                    raise ValueError(error_message)
                return False


def validate_timeline_field_value(field):
    """Check if the Timeline Field value is valid.

    :param field: field value to validate.
    :type field: str

    """
    valid_field_names = [
        "destination_port",
        "http_path",
        "http_user_agent",
        "source_asn",
        "source_org",
        "source_rdns",
        "tag_ids",
        "classification",
    ]

    if field in valid_field_names:
        return True
    else:
        raise ValueError(
            f"Field must be one of the following values: {valid_field_names}"
        )


def validate_timeline_days(days):
    """Check if the Timeline Days value is valid.

    :param days: field value to validate.
    :type days: str

    """
    if isinstance(days, str):
        raise ValueError(
            "Days must be a valid integer between 1 and 90.  Current input is a "
            "string."
        )
    if isinstance(days, int) and 1 <= int(days) <= 90:
        return True
    else:
        raise ValueError("Days must be a valid integer between 1 and 90.")


def validate_timeline_granularity(granularity):
    """Check if the Timeline granularity value is valid.

    :param granularity: field value to validate.
    :type granularity: str

    """
    if granularity != "1h" and granularity != "1d":
        raise ValueError("Granularity currently only supports a value of 1d or 1h")
    else:
        return True


def validate_similar_min_score(min_score):
    """Check if the Similarity min_score value is valid.

    :param min_score: field value to validate.
    :type min_score: str

    """
    if isinstance(min_score, str):
        raise ValueError(
            "Min Score must be a valid integer between 0 and 100.  Current input is a "
            "string."
        )
    if isinstance(min_score, int) and 0 <= int(min_score) <= 100:
        return True
    else:
        raise ValueError("Min Score must be a valid integer between 0 and 100.")


def validate_cve_id(cve_id):
    """Check if provided value is a valid CVE ID

    :param cve_id: field value to validate.
    :type cve_id: str

    """
    # CVE regular expression
    cve_pattern = r"CVE-\d{4}-\d{4,7}"

    pattern = re.compile(cve_pattern)

    if not pattern.match(cve_id):
        raise ValueError("Invalid CVE ID format: {!r}".format(cve_id))
    else:
        return True


def load_template(template_name: str) -> str:
    """Load a template from the templates directory.

    Args:
        template_name: Name of the template to load

    Returns:
        Template content as a string
    """
    template_path = resources.files("greynoise").joinpath(f"templates/{template_name}")
    return template_path.read_text()
