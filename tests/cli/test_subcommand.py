"""CLI subcommands test cases."""

import json
import textwrap
from collections import OrderedDict

import pytest
from click import Context
from click.testing import CliRunner
from mock import Mock, patch
from six import StringIO

from greynoise.cli import main, subcommand
from greynoise.exceptions import RequestFailure
from greynoise.util import CONFIG_FILE


class TestAccount(object):
    """Account subcommand test cases."""

    def test_not_implemented(self):
        """Not implemented error message returned."""
        runner = CliRunner()
        expected_output = "Error: 'account' subcommand is not implemented yet.\n"

        result = runner.invoke(subcommand.account)
        assert result.exit_code == 1
        assert result.output == expected_output


class TestAlerts(object):
    """Alerts subcommand test cases."""

    def test_not_implemented(self):
        """Not implemented error message returned."""
        runner = CliRunner()
        expected_output = "Error: 'alerts' subcommand is not implemented yet.\n"

        result = runner.invoke(subcommand.alerts)
        assert result.exit_code == 1
        assert result.output == expected_output


class TestAnalyze(object):
    """Analyze subcommand test cases."""

    def test_not_implemented(self):
        """Not implemented error message returned."""
        runner = CliRunner()
        expected_output = "Error: 'analyze' subcommand is not implemented yet.\n"

        result = runner.invoke(subcommand.analyze)
        assert result.exit_code == 1
        assert result.output == expected_output


class TestFeedback(object):
    """Feedback subcommand test cases."""

    def test_not_implemented(self):
        """Not implemented error message returned."""
        runner = CliRunner()
        expected_output = "Error: 'feedback' subcommand is not implemented yet.\n"

        result = runner.invoke(subcommand.feedback)
        assert result.exit_code == 1
        assert result.output == expected_output


class TestFilter(object):
    """Filter subcommand test cases."""

    def test_not_implemented(self):
        """Not implemented error message returned."""
        runner = CliRunner()
        expected_output = "Error: 'filter' subcommand is not implemented yet.\n"

        result = runner.invoke(subcommand.filter)
        assert result.exit_code == 1
        assert result.output == expected_output


class TestHelp(object):
    """Help subcommand test cases."""

    def test_help(self):
        """Get help."""
        runner = CliRunner()
        expected_output = "Usage: greynoise [OPTIONS] COMMAND [ARGS]..."

        result = runner.invoke(
            subcommand.help, parent=Context(main, info_name="greynoise")
        )
        assert result.exit_code == 0
        assert expected_output in result.output


class TestInteresting(object):
    """Interesting subcommand test cases."""

    def test_not_implemented(self):
        """Not implemented error message returned."""
        runner = CliRunner()
        expected_output = "Error: 'interesting' subcommand is not implemented yet.\n"

        result = runner.invoke(subcommand.interesting)
        assert result.exit_code == 1
        assert result.output == expected_output


class TestIP(object):
    """IP subcommand tests."""

    @pytest.mark.parametrize("ip_address, expected_response", [("0.0.0.0", {})])
    def test_ip(self, ip_address, expected_response):
        """Get IP address information."""
        runner = CliRunner()

        api_client = Mock()
        api_client.ip.return_value = expected_response
        obj = {"api_client": api_client}

        result = runner.invoke(subcommand.ip, [ip_address], obj=obj)
        assert result.exit_code == 0
        assert result.output.strip("\n") == json.dumps(
            [expected_response], indent=4, sort_keys=True
        )
        api_client.ip.assert_called_with(ip_address=ip_address)

    @pytest.mark.parametrize("ip_address, expected_response", [("0.0.0.0", {})])
    def test_input_file(self, ip_address, expected_response):
        """Get IP address information from input file."""
        runner = CliRunner()
        expected_response = {}

        api_client = Mock()
        api_client.ip.return_value = expected_response
        obj = {
            "api_client": api_client,
            "input_file": StringIO(ip_address),
            "output_format": "json",
            "verbose": False,
        }

        result = runner.invoke(subcommand.ip, obj=obj)
        assert result.exit_code == 0
        assert result.output.strip("\n") == json.dumps(
            [expected_response], indent=4, sort_keys=True
        )
        api_client.ip.assert_called_with(ip_address=ip_address)

    def test_missing_ip_address(self):
        """IP subcommand succeeds even if no ip_address is passed."""
        runner = CliRunner()

        api_client = Mock()
        api_client.ip.return_value = {}
        obj = {
            "api_client": api_client,
            "input_file": None,
            "output_format": "json",
            "verbose": False,
        }

        result = runner.invoke(subcommand.ip, obj=obj)
        assert result.exit_code == 0
        assert result.output == "[]\n"
        api_client.ip.assert_not_called()

    def test_invalid_ip_address(self):
        """IP subcommand fails when ip_address is invalid."""
        runner = CliRunner()

        api_client = Mock()
        api_client.ip.return_value = {}
        obj = {
            "api_client": api_client,
            "input_file": None,
            "output_format": "json",
            "verbose": False,
        }
        expected = 'Error: Invalid value for "[IP_ADDRESS]": not-an-ip\n'

        result = runner.invoke(subcommand.ip, ["not-an-ip"], obj=obj)
        assert result.exit_code == 2
        assert expected in result.output
        api_client.ip.assert_not_called()

    def test_request_failure(self):
        """Error is displayed on API request failure."""
        runner = CliRunner()

        api_client = Mock()
        api_client.ip.side_effect = RequestFailure(
            401, {"error": "forbidden", "status": "error"}
        )
        obj = {
            "api_client": api_client,
            "input_file": None,
            "output_format": "json",
            "verbose": False,
        }
        expected = "API error: forbidden"

        result = runner.invoke(subcommand.ip, ["0.0.0.0"], obj=obj)
        assert result.exit_code == -1
        assert expected in result.output


class TestPCAP(object):
    """PCAP subcommand test cases."""

    def test_not_implemented(self):
        """Not implemented error message returned."""
        runner = CliRunner()
        expected_output = "Error: 'pcap' subcommand is not implemented yet.\n"

        result = runner.invoke(subcommand.pcap)
        assert result.exit_code == 1
        assert result.output == expected_output


class TestQuery(object):
    """"Query subcommand tests."""

    def test_query(self):
        """Run query."""
        runner = CliRunner()

        query = "<query>"
        api_client = Mock()
        api_client.query.return_value = []
        obj = {
            "api_client": api_client,
            "input_file": StringIO(),
            "output_format": "json",
            "verbose": False,
        }
        expected = json.dumps([[]], indent=4, sort_keys=True)

        result = runner.invoke(subcommand.query, [query], obj=obj)
        assert result.exit_code == 0
        assert result.output.strip("\n") == expected
        api_client.query.assert_called_with(query=query)

    def test_request_failure(self):
        """Error is displayed on API request failure."""
        runner = CliRunner()

        api_client = Mock()
        api_client.query.side_effect = RequestFailure(
            401, {"error": "forbidden", "status": "error"}
        )
        obj = {
            "api_client": api_client,
            "input_file": None,
            "output_format": "json",
            "verbose": False,
        }
        expected = "API error: forbidden"

        result = runner.invoke(subcommand.query, ["<query>"], obj=obj)
        assert result.exit_code == -1
        assert expected in result.output


class TestQuick(object):
    """Quick subcommand tests."""

    @pytest.mark.parametrize(
        "ip_address, output_format, expected",
        (
            (
                "0.0.0.0",
                "json",
                json.dumps(
                    [{"ip": "0.0.0.0", "noise": True}], indent=4, sort_keys=True
                ),
            ),
            (
                "0.0.0.0",
                "xml",
                textwrap.dedent(
                    """\
                    <?xml version="1.0" ?>
                    <root>
                    \t<item type="dict">
                    \t\t<ip type="str">0.0.0.0</ip>
                    \t\t<noise type="bool">True</noise>
                    \t</item>
                    </root>"""
                ),
            ),
            ("0.0.0.0", "txt", "0.0.0.0 is classified as NOISE."),
        ),
    )
    def test_quick(self, ip_address, output_format, expected):
        """Quickly check IP address."""
        runner = CliRunner()

        api_client = Mock()
        api_client.quick.return_value = [
            OrderedDict((("ip", ip_address), ("noise", True)))
        ]
        obj = {
            "api_client": api_client,
            "input_file": None,
            "output_format": output_format,
            "verbose": False,
        }

        result = runner.invoke(subcommand.quick, [ip_address], obj=obj)
        assert result.exit_code == 0
        assert result.output.strip("\n") == expected
        api_client.quick.assert_called_with(ip_addresses=[ip_address])

    @pytest.mark.parametrize(
        "ip_addresses, mock_response, expected",
        (
            (
                ["0.0.0.0", "0.0.0.1"],
                [
                    OrderedDict([("ip", "0.0.0.0"), ("noise", True)]),
                    OrderedDict([("ip", "0.0.0.1"), ("noise", False)]),
                ],
                json.dumps(
                    [
                        {"ip": "0.0.0.0", "noise": True},
                        {"ip": "0.0.0.1", "noise": False},
                    ],
                    indent=4,
                    sort_keys=True,
                ),
            ),
        ),
    )
    def test_input_file(self, ip_addresses, mock_response, expected):
        """Quickly check IP address from input file."""
        runner = CliRunner()

        api_client = Mock()
        api_client.quick.return_value = mock_response
        obj = {
            "api_client": api_client,
            "input_file": StringIO("\n".join(ip_addresses)),
            "output_format": "json",
            "verbose": False,
        }

        result = runner.invoke(subcommand.quick, obj=obj)
        assert result.exit_code == 0
        assert result.output.strip("\n") == expected
        api_client.quick.assert_called_with(ip_addresses=ip_addresses)

    def test_missing_ip_address(self):
        """Quick subcommand succeeds even if no ip_address is passed."""
        runner = CliRunner()

        api_client = Mock()
        api_client.quick.return_value = []
        obj = {
            "api_client": api_client,
            "input_file": None,
            "output_format": "json",
            "verbose": False,
        }

        result = runner.invoke(subcommand.quick, [], obj=obj)
        assert result.exit_code == 0
        assert result.output == "[]\n"
        api_client.quick.assert_not_called()

    def test_invalid_ip_address(self):
        """Quick subcommand fails when ip_address is invalid."""
        runner = CliRunner()

        api_client = Mock()
        api_client.quick.return_value = []
        obj = {
            "api_client": api_client,
            "input_file": None,
            "output_format": "json",
            "verbose": False,
        }
        expected = 'Error: Invalid value for "[IP_ADDRESS]...": not-an-ip\n'

        result = runner.invoke(subcommand.quick, ["not-an-ip"], obj=obj)
        assert result.exit_code == 2
        assert expected in result.output
        api_client.quick.assert_not_called()

    def test_request_failure(self):
        """Error is displayed on API request failure."""
        runner = CliRunner()

        api_client = Mock()
        api_client.quick.side_effect = RequestFailure(
            401, {"error": "forbidden", "status": "error"}
        )
        obj = {
            "api_client": api_client,
            "input_file": None,
            "output_format": "json",
            "verbose": False,
        }
        expected = "API error: forbidden"

        result = runner.invoke(subcommand.quick, ["0.0.0.0"], obj=obj)
        assert result.exit_code == -1
        assert expected in result.output


class TestSignature(object):
    """Signature subcommand test cases."""

    def test_not_implemented(self):
        """Not implemented error message returned."""
        runner = CliRunner()
        expected_output = "Error: 'signature' subcommand is not implemented yet.\n"

        result = runner.invoke(subcommand.signature)
        assert result.exit_code == 1
        assert result.output == expected_output


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
            result = runner.invoke(subcommand.setup, [key_option, api_key])
        assert result.exit_code == 0
        assert result.output == expected_output
        save_config.assert_called_with(expected_config)

    def test_missing_api_key(self):
        """Setup fails when api_key is not passed."""
        runner = CliRunner()
        expected_error = 'Error: Missing option "-k" / "--api-key"'

        result = runner.invoke(subcommand.setup, [])
        assert result.exit_code == 2
        assert expected_error in result.output


class TestStats(object):
    """"Stats subcommand tests."""

    def test_stats(self):
        """Run stats query."""
        runner = CliRunner()

        query = "<query>"
        api_client = Mock()
        api_client.stats.return_value = []
        obj = {
            "api_client": api_client,
            "input_file": StringIO(),
            "output_format": "json",
            "verbose": False,
        }
        expected = json.dumps([[]], indent=4, sort_keys=True)

        result = runner.invoke(subcommand.stats, [query], obj=obj)
        assert result.exit_code == 0
        assert result.output.strip("\n") == expected
        api_client.stats.assert_called_with(query=query)

    def test_request_failure(self):
        """Error is displayed on API request failure."""
        runner = CliRunner()

        api_client = Mock()
        api_client.stats.side_effect = RequestFailure(
            401, {"error": "forbidden", "status": "error"}
        )
        obj = {
            "api_client": api_client,
            "input_file": None,
            "output_format": "json",
            "verbose": False,
        }
        expected = "API error: forbidden"

        result = runner.invoke(subcommand.stats, ["<query>"], obj=obj)
        assert result.exit_code == -1
        assert expected in result.output


class TestVersion(object):
    """Version subcommand test cases."""

    def test_not_implemented(self):
        """Not implemented error message returned."""
        runner = CliRunner()
        expected_output = "Error: 'version' subcommand is not implemented yet.\n"

        result = runner.invoke(subcommand.version)
        assert result.exit_code == 1
        assert result.output == expected_output
