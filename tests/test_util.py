"""Utility functions test cases."""

import textwrap

import pytest

from mock import patch
from six import StringIO

from greynoise.util import load_config, save_config, validate_ip


class TestLoadConfig(object):
    """Load configuration test cases."""

    @patch("greynoise.util.os")
    def test_default_api_key(self, os):
        """API key set to empty string by default"""
        os.environ = {}
        os.path.isfile.return_value = False

        config = load_config()
        assert config["api_key"] == ""

    @patch("greynoise.util.open")
    @patch("greynoise.util.os")
    def test_api_key_from_configuration_file(self, os, open):
        """API key value retrieved from configuration file."""
        expected = "<api_key>"

        os.environ = {}
        os.path.isfile.return_value = True
        file_content = textwrap.dedent(
            """\
            [greynoise]
            api_key = {}
            """.format(
                expected
            )
        )
        open().__enter__.return_value = StringIO(file_content)

        config = load_config()
        assert config["api_key"] == expected
        open().__enter__.assert_called()

    @patch("greynoise.util.open")
    @patch("greynoise.util.os")
    def test_api_key_from_environment_variable(self, os, open):
        """API key value retrieved from environment variable."""
        expected = "<api_key>"

        os.environ = {"GREYNOISE_API_KEY": expected}
        os.path.isfile.return_value = True
        file_content = textwrap.dedent(
            """\
            [greynoise]
            api_key = unexpected
            """
        )
        open().__enter__.return_value = StringIO(file_content)

        config = load_config()
        assert config["api_key"] == expected
        open().__enter__.assert_called()


class TestSaveConfig(object):
    """Save configuration to a file test cases."""

    def test_save_config(self):
        """Configuration written to a file."""
        api_key = "<api_key>"
        config = {"api_key": "<api_key>"}
        expected = textwrap.dedent(
            """\
            [greynoise]
            api_key = {}

            """.format(
                api_key
            )
        )

        with patch("greynoise.util.open") as open_:
            config_file = StringIO()
            open_().__enter__.return_value = config_file
            save_config(config)

        assert config_file.getvalue() == expected


class TestValidateIP(object):
    """IP validation test cases."""

    @pytest.mark.parametrize("ip", ("0.0.0.0", "255.255.255.255", "192.168.1.0"))
    def test_valid(self, ip):
        """Valid ip address values."""
        validate_ip(ip)

    @pytest.mark.parametrize("ip", ("0.0.0.-1", "255.255.255.256", "not an ip address"))
    def test_invalid(self, ip):
        """Invalid ip address values."""
        with pytest.raises(ValueError) as exception:
            validate_ip(ip)
        assert str(exception.value) == "Invalid IP address: {!r}".format(ip)
