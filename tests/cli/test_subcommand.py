"""CLI subcommands test cases."""

import textwrap

import pytest
from click.testing import CliRunner
from mock import Mock, patch

from greynoise.cli.subcommand import (
    actors,
    context,
    gnql,
    multi_quick_check,
    quick_check,
    setup,
    stats,
)
from greynoise.util import CONFIG_FILE


class TestSetup(object):
    """Setup subcommand test cases."""

    @pytest.mark.parametrize("key_option", ["-k", "--api-key"])
    def test_save_config(self, key_option):
        """Save configuration file."""
        runner = CliRunner()
        api_key = "<api_key>"
        expected_config = {"api_key": api_key}
        expected_output = "Configuration saved to {!r}\n".format(CONFIG_FILE)

        with patch("greynoise.cli.subcommand.save_config") as save_config:
            result = runner.invoke(setup, [key_option, api_key])
        assert result.exit_code == 0
        assert result.output == expected_output
        save_config.assert_called_with(expected_config)

    def test_missing_api_key(self):
        """Setup fails when api_key is not passed."""
        runner = CliRunner()
        expected_error = 'Error: Missing option "-k" / "--api-key"'

        result = runner.invoke(setup, [])
        assert result.exit_code == 2
        assert expected_error in result.output


class TestContext(object):
    """Context subcommand tests."""

    def test_context(self):
        """Get IP address context."""
        runner = CliRunner()

        api_client = Mock()
        api_client.get_context.return_value = {}
        obj = {"api_client": api_client, "output_format": "json", "verbose": False}

        result = runner.invoke(context, ["0.0.0.0"], obj=obj)
        assert result.exit_code == 0
        assert result.output == "{}\n"
        api_client.get_context.assert_called_with(ip_address="0.0.0.0")

    def test_missing_ip_address(self):
        """Context fails when ip_address is missing."""
        runner = CliRunner()

        api_client = Mock()
        api_client.get_context.return_value = {}
        obj = {"api_client": api_client, "output_format": "json", "verbose": False}
        expected = 'Error: Missing argument "IP_ADDRESS".'

        result = runner.invoke(context, [], obj=obj)
        assert result.exit_code == 2
        assert expected in result.output
        api_client.get_context.assert_not_called()

    def test_invalid_ip_address(self):
        """Context fails when ip_address is invalid."""
        runner = CliRunner()

        api_client = Mock()
        api_client.get_context.return_value = {}
        obj = {"api_client": api_client, "output_format": "json", "verbose": False}
        expected = 'Error: Invalid value for "IP_ADDRESS": not-an-ip\n'

        result = runner.invoke(context, ["not-an-ip"], obj=obj)
        assert result.exit_code == 2
        assert expected in result.output
        api_client.get_context.assert_not_called()


class TestQuickCheck(object):
    """Quick check subcommand tests."""

    @pytest.mark.parametrize(
        "output_format, expected",
        (
            (
                "json",
                textwrap.dedent(
                    """\
                    {
                        "ip": "0.0.0.0",
                        "noise": true
                    }
                    """
                ),
            ),
            (
                "xml",
                textwrap.dedent(
                    """\
                    <?xml version="1.0" ?>
                    <root>
                    \t<ip type="str">0.0.0.0</ip>
                    \t<noise type="bool">True</noise>
                    </root>
                    """
                ),
            ),
            ("txt", "0.0.0.0 is classified as NOISE.\n"),
        ),
    )
    def test_quick_check(self, output_format, expected):
        """Quickly check IP address."""
        runner = CliRunner()

        api_client = Mock()
        api_client.get_noise_status.return_value = {"ip": "0.0.0.0", "noise": True}
        obj = {
            "api_client": api_client,
            "output_format": output_format,
            "verbose": False,
        }

        result = runner.invoke(quick_check, ["0.0.0.0"], obj=obj)
        assert result.exit_code == 0
        assert result.output == expected
        api_client.get_noise_status.assert_called_with(ip_address="0.0.0.0")

    def test_missing_ip_address(self):
        """Quick check fails when ip_address is missing."""
        runner = CliRunner()

        api_client = Mock()
        api_client.get_noise_status.return_value = {}
        obj = {"api_client": api_client, "output_format": "json", "verbose": False}
        expected = 'Error: Missing argument "IP_ADDRESS".'

        result = runner.invoke(quick_check, [], obj=obj)
        assert result.exit_code == 2
        assert expected in result.output
        api_client.get_noise_status.assert_not_called()

    def test_invalid_ip_address(self):
        """Quick check fails when ip_address is invalid."""
        runner = CliRunner()

        api_client = Mock()
        api_client.get_noise_status.return_value = {}
        obj = {"api_client": api_client, "output_format": "json", "verbose": False}
        expected = 'Error: Invalid value for "IP_ADDRESS": not-an-ip\n'

        result = runner.invoke(quick_check, ["not-an-ip"], obj=obj)
        assert result.exit_code == 2
        assert expected in result.output
        api_client.get_noise_status.assert_not_called()


class TestMultiQuickCheck(object):
    """Multi quick check subcommand tests."""

    def test_quick_check(self):
        """Quickly check IP addresses."""
        runner = CliRunner()

        api_client = Mock()
        api_client.get_noise_status_bulk.return_value = []
        obj = {"api_client": api_client, "output_format": "json", "verbose": False}

        result = runner.invoke(multi_quick_check, ["0.0.0.0", "0.0.0.1"], obj=obj)
        assert result.exit_code == 0
        assert result.output == "[]\n"
        api_client.get_noise_status_bulk.assert_called_with(
            ip_addresses=["0.0.0.0", "0.0.0.1"]
        )

    def test_missing_ip_address(self):
        """Quick check calls API even when no addresses are passed."""
        runner = CliRunner()

        api_client = Mock()
        api_client.get_noise_status_bulk.return_value = {"error": "no results"}
        obj = {"api_client": api_client, "output_format": "json", "verbose": False}
        expected = textwrap.dedent(
            """\
            {
                "error": "no results"
            }
        """
        )

        result = runner.invoke(multi_quick_check, [], obj=obj)
        assert result.exit_code == 0
        assert result.output == expected
        api_client.get_noise_status_bulk.assert_called_with(ip_addresses=[])

    def test_invalid_ip_address(self):
        """Quick check fails when ip_address is invalid."""
        runner = CliRunner()

        api_client = Mock()
        api_client.get_noise_status_bulk.return_value = {}
        obj = {"api_client": api_client, "output_format": "json", "verbose": False}
        expected = 'Error: Invalid value for "[IP_ADDRESS]...": not-an-ip\n'

        result = runner.invoke(multi_quick_check, ["0.0.0.0", "not-an-ip"], obj=obj)
        assert result.exit_code == 2
        assert expected in result.output
        api_client.get_noise_status_bulk.assert_not_called()


class TestActors(object):
    """Actors subcommand tests."""

    def test_actors(self):
        """Get actors."""
        runner = CliRunner()

        api_client = Mock()
        api_client.get_actors.return_value = []
        obj = {"api_client": api_client, "output_format": "json", "verbose": False}
        expected = "[]\n"

        result = runner.invoke(actors, obj=obj)
        assert result.exit_code == 0
        assert result.output == expected
        api_client.get_actors.assert_called_with()


class TestGNQL(object):
    """"GNQL subcommand tests."""

    def test_gnql(self):
        """Run GQNQL query."""
        runner = CliRunner()

        query = "<query>"
        api_client = Mock()
        api_client.run_query.return_value = []
        obj = {"api_client": api_client, "output_format": "json", "verbose": False}
        expected = "[]\n"

        result = runner.invoke(gnql, [query], obj=obj)
        assert result.exit_code == 0
        assert result.output == expected
        api_client.run_query.assert_called_with(query=query)


class TestStats(object):
    """"GNQL stats subcommand tests."""

    def test_stats(self):
        """Run GQNQL stats query."""
        runner = CliRunner()

        query = "<query>"
        api_client = Mock()
        api_client.run_stats_query.return_value = []
        obj = {"api_client": api_client, "output_format": "json", "verbose": False}
        expected = "[]\n"

        result = runner.invoke(stats, [query], obj=obj)
        assert result.exit_code == 0
        assert result.output == expected
        api_client.run_stats_query.assert_called_with(query=query)
