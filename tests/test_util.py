"""Utility functions test cases."""

import os
import textwrap
from unittest.mock import patch

import pytest
from six import StringIO

from greynoise.util import (
    CONFIG_FILE,
    load_config,
    save_config,
    validate_ip,
    validate_similar_min_score,
    validate_timeline_days,
    validate_timeline_field_value,
    validate_timeline_granularity,
)


class TestLoadConfig(object):
    """Load configuration test cases."""

    @patch("greynoise.util.os")
    def test_defaults(self, os):
        """Default values returned if configuration file is not found."""
        os.environ = {}
        os.path.isfile.return_value = False

        config = load_config()
        assert config == {
            "api_key": "",
            "api_server": "https://api.greynoise.io",
            "timeout": 60,
            "proxy": "",
            "offering": "enterprise",
            "cache_max_size": 1000000,
            "cache_ttl": 3600,
            "use_cache": True,
        }

    @patch("greynoise.util.open")
    @patch("greynoise.util.os")
    def test_values_from_configuration_file(self, os, open):
        """Values retrieved from configuration file."""
        expected = {
            "api_key": "<api_key>",
            "api_server": "<api_server",
            "timeout": 123456,
            "proxy": "",
            "offering": "enterprise",
            "cache_max_size": 1000000,
            "cache_ttl": 3600,
            "use_cache": True,
        }

        os.environ = {}
        os.path.isfile.return_value = True
        file_content = textwrap.dedent(
            """\
            [greynoise]
            api_key = {}
            api_server = {}
            timeout = {}
            proxy = {}
            offering = {}
            """.format(
                expected["api_key"],
                expected["api_server"],
                expected["timeout"],
                expected["proxy"],
                expected["offering"],
            )
        )
        open().__enter__.return_value = StringIO(file_content)

        config = load_config()
        assert config == expected
        open().__enter__.assert_called()

    @patch("greynoise.util.open")
    @patch("greynoise.util.os")
    def test_api_key_from_environment_variable(self, os, open):
        """API key value retrieved from environment variable."""
        expected = {
            "api_key": "<api_key>",
            "api_server": "<api_server>",
            "timeout": 123456,
            "proxy": "",
            "offering": "enterprise",
            "cache_max_size": 1000000,
            "cache_ttl": 3600,
            "use_cache": True,
        }

        os.environ = {"GREYNOISE_API_KEY": expected["api_key"]}
        os.path.isfile.return_value = True
        file_content = textwrap.dedent(
            """\
            [greynoise]
            api_key = unexpected
            api_server = {}
            timeout = {}
            proxy = {}
            offering = {}
            """.format(
                expected["api_server"],
                expected["timeout"],
                expected["proxy"],
                expected["offering"],
            )
        )
        open().__enter__.return_value = StringIO(file_content)

        config = load_config()
        assert config == expected
        open().__enter__.assert_called()

    @patch("greynoise.util.open")
    @patch("greynoise.util.os")
    def test_api_server_from_environment_variable(self, os, open):
        """API server value retrieved from environment variable."""
        expected = {
            "api_key": "<api_key>",
            "api_server": "<api_server>",
            "timeout": 123456,
            "proxy": "",
            "offering": "enterprise",
            "cache_max_size": 1000000,
            "cache_ttl": 3600,
            "use_cache": True,
        }

        os.environ = {"GREYNOISE_API_SERVER": expected["api_server"]}
        os.path.isfile.return_value = True
        file_content = textwrap.dedent(
            """\
            [greynoise]
            api_key = {}
            api_server = unexpected
            timeout = {}
            proxy = {}
            offering = {}
            """.format(
                expected["api_key"],
                expected["timeout"],
                expected["proxy"],
                expected["offering"],
            )
        )
        open().__enter__.return_value = StringIO(file_content)

        config = load_config()
        assert config == expected
        open().__enter__.assert_called()

    @patch("greynoise.util.open")
    @patch("greynoise.util.os")
    def test_timeout_from_environment_variable(self, os, open):
        """Timeout value retrieved from environment variable."""
        expected = {
            "api_key": "<api_key>",
            "api_server": "<api_server>",
            "timeout": 123456,
            "proxy": "",
            "offering": "enterprise",
            "cache_max_size": 1000000,
            "cache_ttl": 3600,
            "use_cache": True,
        }

        os.environ = {"GREYNOISE_TIMEOUT": str(expected["timeout"])}
        os.path.isfile.return_value = True
        file_content = textwrap.dedent(
            """\
            [greynoise]
            api_key = {}
            api_server = {}
            timeout = unexpected
            proxy = {}
            offering = {}
            """.format(
                expected["api_key"],
                expected["api_server"],
                expected["proxy"],
                expected["offering"],
            )
        )
        open().__enter__.return_value = StringIO(file_content)

        config = load_config()
        assert config == expected
        open().__enter__.assert_called()

    @patch("greynoise.util.open")
    @patch("greynoise.util.os")
    def test_offering_from_environment_variable(self, os, open):
        """API key value retrieved from environment variable."""
        expected = {
            "api_key": "<api_key>",
            "api_server": "<api_server>",
            "timeout": 123456,
            "proxy": "",
            "offering": "enterprise",
            "cache_max_size": 1000000,
            "cache_ttl": 3600,
            "use_cache": True,
        }

        os.environ = {"GREYNOISE_OFFERING": expected["offering"]}
        os.path.isfile.return_value = True
        file_content = textwrap.dedent(
            """\
            [greynoise]
            api_key = {}
            api_server = {}
            timeout = {}
            proxy = {}
            offering = unexpected
            """.format(
                expected["api_key"],
                expected["api_server"],
                expected["timeout"],
                expected["proxy"],
            )
        )
        open().__enter__.return_value = StringIO(file_content)

        config = load_config()
        assert config == expected
        open().__enter__.assert_called()

    @patch("greynoise.util.open")
    @patch("greynoise.util.os")
    def test_timeout_from_environment_variable_with_invalid_value(self, os, open):
        """Invalid timeout value in environment variable is ignored."""
        expected = {
            "api_key": "<api_key>",
            "api_server": "<api_server>",
            "timeout": 60,
            "proxy": "",
            "offering": "enterprise",
            "cache_max_size": 1000000,
            "cache_ttl": 3600,
            "use_cache": True,
        }

        os.environ = {"GREYNOISE_TIMEOUT": "invalid"}
        os.path.isfile.return_value = True
        file_content = textwrap.dedent(
            """\
            [greynoise]
            api_key = {}
            api_server = {}
            timeout = {}
            proxy = {}
            offering = {}
            """.format(
                expected["api_key"],
                expected["api_server"],
                expected["timeout"],
                expected["proxy"],
                expected["offering"],
            )
        )
        open().__enter__.return_value = StringIO(file_content)

        config = load_config()
        assert config == expected
        open().__enter__.assert_called()


class TestSaveConfig(object):
    """Save configuration to a file test cases."""

    def test_save_config_dir_created(self):
        """Configuration directory created if missing."""
        config = {
            "api_key": "<api_key>",
            "api_server": "<api_server>",
            "timeout": 123456,
            "proxy": "",
            "offering": "enterprise",
        }

        with patch("greynoise.util.os") as os, patch("greynoise.util.open") as open_:
            os.path.isdir.return_value = False
            config_file = StringIO()
            open_().__enter__.return_value = config_file
            save_config(config)

        os.makedirs.assert_called_with(os.path.dirname(CONFIG_FILE))

    def test_save_config_file_written(self):
        """Configuration written to a file."""
        config = {
            "api_key": "<api_key>",
            "api_server": "<api_server>",
            "timeout": 123456,
            "proxy": "",
            "offering": "enterprise",
        }
        expected = textwrap.dedent(
            """\
            [greynoise]
            api_key = {}
            api_server = {}
            timeout = {}
            proxy = {}
            offering = {}\n
            """.format(
                config["api_key"],
                config["api_server"],
                config["timeout"],
                config["proxy"],
                config["offering"],
            )
        )

        with patch("greynoise.util.os") as os, patch("greynoise.util.open") as open_:
            os.path.isdir.return_value = True
            config_file = StringIO()
            open_().__enter__.return_value = config_file
            save_config(config)

        assert config_file.getvalue() == expected


class TestValidateIP(object):
    """IP validation test cases."""

    @pytest.mark.parametrize("ip", ("123.123.123.123", "68.62.43.1", "8.8.8.8"))
    def test_valid(self, ip):
        """Valid ip address values."""
        validate_ip(ip)

    @pytest.mark.parametrize("ip", ("0.0.0.-1", "255.255.255.256", "not an ip address"))
    def test_invalid(self, ip):
        """Invalid ip address values."""
        with pytest.raises(ValueError) as exception:
            validate_ip(ip)
        assert str(exception.value) == "Invalid IP address: {!r}".format(ip)

    @pytest.mark.parametrize("ip", ("0.0.0.0", "255.255.255.255", "192.168.1.0"))
    def test_non_routable(self, ip):
        """Invalid ip address values."""
        with pytest.raises(ValueError) as exception:
            validate_ip(ip)
        assert str(exception.value) == "Non-Routable IP address: {!r}".format(ip)


class TestValidateSimilarMinScore(object):
    """Similarity min score utility validation test cases."""

    @pytest.mark.parametrize("min_score", (0, 50, 100))
    def test_valid(self, min_score):
        """Test valid values."""
        validate_similar_min_score(min_score)

    @pytest.mark.parametrize("min_score", (-1, 500))
    def test_invalid(self, min_score):
        """Test invalid values."""
        with pytest.raises(ValueError) as exception:
            validate_similar_min_score(min_score)
        assert (
            str(exception.value)
            == "Min Score must be a valid integer between 0 and 100."
        )

    @pytest.mark.parametrize("min_score", ("0", "5", "100"))
    def test_string(self, min_score):
        """Test string input values."""
        with pytest.raises(ValueError) as exception:
            validate_similar_min_score(min_score)
        assert (
            str(exception.value)
            == "Min Score must be a valid integer between 0 and 100.  "
            "Current input is a string."
        )


class TestValidateTimelineGranularity(object):
    """Timeline granularity utility validation test cases."""

    @pytest.mark.parametrize("granularity", ("1h", "1d"))
    def test_valid(self, granularity):
        """Test valid values."""
        validate_timeline_granularity(granularity)

    @pytest.mark.parametrize("granularity", (-1, 500))
    def test_invalid(self, granularity):
        """Test invalid values."""
        with pytest.raises(ValueError) as exception:
            validate_timeline_granularity(granularity)
        assert (
            str(exception.value)
            == "Granularity currently only supports a value of 1d or 1h"
        )


class TestValidateTimelineDays(object):
    """Timeline days utility validation test cases."""

    @pytest.mark.parametrize("days", (1, 15, 30))
    def test_valid(self, days):
        """Test valid values."""
        validate_timeline_days(days)

    @pytest.mark.parametrize("days", (-1, 500))
    def test_invalid(self, days):
        """Test invalid values."""
        with pytest.raises(ValueError) as exception:
            validate_timeline_days(days)
        assert str(exception.value) == "Days must be a valid integer between 1 and 90."

    @pytest.mark.parametrize("days", ("0", "5", "100"))
    def test_string(self, days):
        """Test string input values."""
        with pytest.raises(ValueError) as exception:
            validate_timeline_days(days)
        assert (
            str(exception.value) == "Days must be a valid integer between 1 and 90.  "
            "Current input is a string."
        )


class TestValidateTimelineField(object):
    """Timeline field utility validation test cases."""

    @pytest.mark.parametrize(
        "field", ("destination_port", "http_path", "http_user_agent")
    )
    def test_valid(self, field):
        """Test valid values."""
        validate_timeline_field_value(field)

    @pytest.mark.parametrize("field", ("http_user_agents", "invalid_field"))
    def test_invalid(self, field):
        """Test invalid values."""
        with pytest.raises(ValueError) as exception:
            validate_timeline_field_value(field)
        assert (
            str(exception.value)
            == "Field must be one of the following values: ['destination_port', "
            "'http_path', 'http_user_agent', 'source_asn', 'source_org', "
            "'source_rdns', 'tag_ids', 'classification']"
        )


def test_load_config_cache_settings():
    """Test loading cache settings from environment variables."""
    with patch.dict(
        os.environ,
        {
            "GREYNOISE_CACHE_MAX_SIZE": "2000000",
            "GREYNOISE_CACHE_TTL": "7200",
        },
    ):
        config = load_config()
        assert config["cache_max_size"] == 2000000
        assert config["cache_ttl"] == 7200


def test_save_config_cache_settings():
    """Test saving cache settings to configuration file."""
    config = {
        "api_key": "test-api-key",
        "api_server": "https://api.greynoise.io",
        "timeout": 30,
        "proxy": "",
        "offering": "enterprise",
        "cache_max_size": 2000000,
        "cache_ttl": 7200,
    }
    expected = textwrap.dedent(
        """\
        [greynoise]
        api_key = {}
        api_server = {}
        timeout = {}
        proxy = {}
        offering = {}
        cache_max_size = {}
        cache_ttl = {}\n
        """.format(
            config["api_key"],
            config["api_server"],
            config["timeout"],
            config["proxy"],
            config["offering"],
            config["cache_max_size"],
            config["cache_ttl"],
        )
    )

    with patch("greynoise.util.os") as os, patch("greynoise.util.open") as open_:
        os.path.isdir.return_value = True
        config_file = StringIO()
        open_().__enter__.return_value = config_file
        save_config(config)

    assert config_file.getvalue() == expected


class TestConfiguration:
    """Test configuration scenarios."""

    def test_environment_variables(self):
        """Test configuration loading from environment variables."""
        with patch.dict(
            os.environ,
            {
                "GREYNOISE_API_KEY": "test-key",
                "GREYNOISE_API_SERVER": "https://test.api.greynoise.io",
                "GREYNOISE_TIMEOUT": "60",
                "GREYNOISE_OFFERING": "enterprise",
            },
        ):
            config = load_config()
            assert config["api_key"] == "test-key"
            assert config["api_server"] == "https://test.api.greynoise.io"
            assert config["timeout"] == 60
            assert config["offering"] == "enterprise"

    def test_invalid_configuration(self, tmp_path):
        """Test handling of invalid configuration."""
        config_file = tmp_path / "config.ini"
        config_file.write_text(
            """
[greynoise]
api_key = test-key
timeout = invalid
"""
        )

        with patch("greynoise.util.CONFIG_FILE", str(config_file)):
            print("CONFIG_FILE")
            print(CONFIG_FILE)
            config = load_config()
            print("config")
            print(config)
            assert config["timeout"] == 60  # Should use default value

            # Test invalid timeout
        with patch.dict(os.environ, {"GREYNOISE_TIMEOUT": "invalid"}):
            config = load_config()
            assert config["timeout"] == 60  # Should use default value

        # Test invalid cache max size
        with patch.dict(os.environ, {"GREYNOISE_CACHE_MAX_SIZE": "invalid"}):
            config = load_config()
            assert config["cache_max_size"] == 1000000  # Should use default value

        # Test invalid cache ttl
        with patch.dict(os.environ, {"GREYNOISE_CACHE_TTL": "invalid"}):
            config = load_config()
            assert config["cache_ttl"] == 3600  # Should use default value

    def test_configuration_validation(self):
        """Test configuration validation."""
        # Test valid configuration
        with patch.dict(
            os.environ,
            {
                "GREYNOISE_API_KEY": "test-key",
                "GREYNOISE_API_SERVER": "https://api.greynoise.io",
                "GREYNOISE_TIMEOUT": "30",
                "GREYNOISE_OFFERING": "enterprise",
            },
        ):
            config = load_config()
            assert config["api_key"] == "test-key"
            assert config["api_server"] == "https://api.greynoise.io"
            assert config["timeout"] == 30
            assert config["offering"] == "enterprise"
