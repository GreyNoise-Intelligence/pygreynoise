"""CLI subcommands test cases."""

import json
import textwrap
from collections import OrderedDict

import pytest
from click import Context
from click.testing import CliRunner
from mock import patch
from six import StringIO

from greynoise.cli import main, subcommand
from greynoise.exceptions import RequestFailure
from greynoise.util import CONFIG_FILE


@pytest.fixture
def api_client():
    load_config_patcher = patch("greynoise.cli.decorator.load_config")
    api_client_cls_patcher = patch("greynoise.cli.decorator.GreyNoise")
    with load_config_patcher as load_config:
        load_config.return_value = {"api_key": "<api_key>"}
        with api_client_cls_patcher as api_client_cls:
            api_client = api_client_cls()
            yield api_client


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
    def test_ip(self, api_client, ip_address, expected_response):
        """Get IP address information."""
        runner = CliRunner()

        api_client.ip.return_value = expected_response

        result = runner.invoke(subcommand.ip, ["-f", "json", ip_address])
        assert result.exit_code == 0
        assert result.output.strip("\n") == json.dumps(
            [expected_response], indent=4, sort_keys=True
        )
        api_client.ip.assert_called_with(ip_address=ip_address)

    @pytest.mark.parametrize("ip_address, expected_response", [("0.0.0.0", {})])
    def test_input_file(self, api_client, ip_address, expected_response):
        """Get IP address information from input file."""
        runner = CliRunner()

        api_client.ip.return_value = expected_response

        result = runner.invoke(
            subcommand.ip, ["-f", "json", "-i", StringIO(ip_address)]
        )
        assert result.exit_code == 0
        assert result.output.strip("\n") == json.dumps(
            [expected_response], indent=4, sort_keys=True
        )
        api_client.ip.assert_called_with(ip_address=ip_address)

    def test_no_ip_address_passed(self, api_client):
        """Usage is returned if no IP address or input file is passed."""
        runner = CliRunner()

        result = runner.invoke(
            subcommand.ip, parent=Context(main, info_name="greynoise")
        )
        assert result.exit_code == -1
        assert "Usage: greynoise ip" in result.output
        api_client.ip.assert_not_called()

    def test_input_file_invalid_ip_addresses_passsed(self, api_client):
        """Error returned if only invalid IP addresses are passed in input file."""
        runner = CliRunner()

        expected = (
            "Error: at least one valid IP address must be passed either as an "
            "argument (IP_ADDRESS) or through the -i/--input_file option."
        )

        result = runner.invoke(
            subcommand.ip,
            ["-i", StringIO("not-an-ip")],
            parent=Context(main, info_name="greynoise"),
        )
        assert result.exit_code == -1
        assert "Usage: greynoise ip" in result.output
        assert expected in result.output
        api_client.ip.assert_not_called()

    def test_invalid_ip_address_as_argument(self, api_client):
        """IP subcommand fails when ip_address is invalid."""
        runner = CliRunner()

        expected = 'Error: Invalid value for "[IP_ADDRESS]": not-an-ip\n'

        result = runner.invoke(subcommand.ip, ["not-an-ip"])
        assert result.exit_code == 2
        assert expected in result.output
        api_client.ip.assert_not_called()

    def test_request_failure(self, api_client):
        """Error is displayed on API request failure."""
        runner = CliRunner()

        api_client.ip.side_effect = RequestFailure(
            401, {"error": "forbidden", "status": "error"}
        )
        expected = "API error: forbidden"

        result = runner.invoke(subcommand.ip, ["0.0.0.0"])
        assert result.exit_code == -1
        assert expected in result.output

    def test_api_key_not_found(self):
        """Error is displayed if API key is not found."""
        runner = CliRunner()

        with patch("greynoise.cli.decorator.load_config") as load_config:
            load_config.return_value = {"api_key": ""}
            result = runner.invoke(
                subcommand.ip, ["0.0.0.0"], parent=Context(main, info_name="greynoise")
            )
            assert result.exit_code == -1
            assert "Error: API key not found" in result.output


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

    def test_query(self, api_client):
        """Run query."""
        runner = CliRunner()

        query = "<query>"
        api_client.query.return_value = []
        expected = json.dumps([[]], indent=4, sort_keys=True)

        result = runner.invoke(subcommand.query, ["-f", "json", query])
        assert result.exit_code == 0
        assert result.output.strip("\n") == expected
        api_client.query.assert_called_with(query=query)

    def test_input_file(self, api_client):
        """Run query from input file."""
        runner = CliRunner()

        query = "<query>"
        api_client.query.return_value = []
        expected = json.dumps([[]], indent=4, sort_keys=True)

        result = runner.invoke(subcommand.query, ["-f", "json", "-i", StringIO(query)])
        assert result.exit_code == 0
        assert result.output.strip("\n") == expected
        api_client.query.assert_called_with(query=query)

    def test_no_query_passed(self, api_client):
        """Usage is returned if no query or input file is passed."""
        runner = CliRunner()

        result = runner.invoke(
            subcommand.query, parent=Context(main, info_name="greynoise")
        )
        assert result.exit_code == -1
        assert "Usage: greynoise query" in result.output
        api_client.query.assert_not_called()

    def test_empty_input_file(self, api_client):
        """Error is returned if empty input fle is passed."""
        runner = CliRunner()

        expected = (
            "Error: at least one query must be passed either as an argument "
            "(QUERY) or through the -i/--input_file option."
        )

        result = runner.invoke(
            subcommand.query,
            ["-i", StringIO()],
            parent=Context(main, info_name="greynoise"),
        )
        assert result.exit_code == -1
        assert "Usage: greynoise query" in result.output
        assert expected in result.output
        api_client.query.assert_not_called()

    def test_request_failure(self, api_client):
        """Error is displayed on API request failure."""
        runner = CliRunner()

        api_client.query.side_effect = RequestFailure(
            401, {"error": "forbidden", "status": "error"}
        )
        expected = "API error: forbidden"

        result = runner.invoke(subcommand.query, ["<query>"])
        assert result.exit_code == -1
        assert expected in result.output

    def test_api_key_not_found(self):
        """Error is displayed if API key is not found."""
        runner = CliRunner()

        with patch("greynoise.cli.decorator.load_config") as load_config:
            load_config.return_value = {"api_key": ""}
            result = runner.invoke(
                subcommand.query,
                ["<query>"],
                parent=Context(main, info_name="greynoise"),
            )
            assert result.exit_code == -1
            assert "Error: API key not found" in result.output


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
    def test_quick(self, api_client, ip_address, output_format, expected):
        """Quickly check IP address."""
        runner = CliRunner()

        api_client.quick.return_value = [
            OrderedDict((("ip", ip_address), ("noise", True)))
        ]

        result = runner.invoke(subcommand.quick, ["-f", output_format, ip_address])
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
    def test_input_file(self, api_client, ip_addresses, mock_response, expected):
        """Quickly check IP address from input file."""
        runner = CliRunner()

        api_client.quick.return_value = mock_response

        result = runner.invoke(
            subcommand.quick, ["-f", "json", "-i", StringIO("\n".join(ip_addresses))]
        )
        assert result.exit_code == 0
        assert result.output.strip("\n") == expected
        api_client.quick.assert_called_with(ip_addresses=ip_addresses)

    def test_no_ip_address_passed(self, api_client):
        """Usage is returned if no IP address or input file is passed."""
        runner = CliRunner()

        result = runner.invoke(
            subcommand.quick, parent=Context(main, info_name="greynoise")
        )
        assert result.exit_code == -1
        assert "Usage: greynoise quick" in result.output
        api_client.quick.assert_not_called()

    def test_input_file_invalid_ip_addresses_passsed(self, api_client):
        """Error returned if only invalid IP addresses are passed in input file."""
        runner = CliRunner()

        expected = (
            "Error: at least one valid IP address must be passed either as an "
            "argument (IP_ADDRESS) or through the -i/--input_file option."
        )

        result = runner.invoke(
            subcommand.quick,
            ["-i", StringIO("not-an-ip")],
            parent=Context(main, info_name="greynoise"),
        )
        assert result.exit_code == -1
        assert "Usage: greynoise quick" in result.output
        assert expected in result.output
        api_client.quick.assert_not_called()

    def test_invalid_ip_address_as_argument(self, api_client):
        """Quick subcommand fails when ip_address is invalid."""
        runner = CliRunner()

        expected = 'Error: Invalid value for "[IP_ADDRESS]...": not-an-ip\n'

        result = runner.invoke(subcommand.quick, ["not-an-ip"])
        assert result.exit_code == 2
        assert expected in result.output
        api_client.quick.assert_not_called()

    def test_request_failure(self, api_client):
        """Error is displayed on API request failure."""
        runner = CliRunner()

        api_client.quick.side_effect = RequestFailure(
            401, {"error": "forbidden", "status": "error"}
        )
        expected = "API error: forbidden"

        result = runner.invoke(subcommand.quick, ["0.0.0.0"])
        assert result.exit_code == -1
        assert expected in result.output

    def test_api_key_not_found(self):
        """Error is displayed if API key is not found."""
        runner = CliRunner()

        with patch("greynoise.cli.decorator.load_config") as load_config:
            load_config.return_value = {"api_key": ""}
            result = runner.invoke(
                subcommand.quick,
                ["0.0.0.0"],
                parent=Context(main, info_name="greynoise"),
            )
            assert result.exit_code == -1
            assert "Error: API key not found" in result.output


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

    def test_stats(self, api_client):
        """Run stats query."""
        runner = CliRunner()

        query = "<query>"
        api_client.stats.return_value = []
        expected = json.dumps([[]], indent=4, sort_keys=True)

        result = runner.invoke(subcommand.stats, ["-f", "json", query])
        assert result.exit_code == 0
        assert result.output.strip("\n") == expected
        api_client.stats.assert_called_with(query=query)

    def test_input_file(self, api_client):
        """Run stats query from input file."""
        runner = CliRunner()

        query = "<query>"
        api_client.stats.return_value = []
        expected = json.dumps([[]], indent=4, sort_keys=True)

        result = runner.invoke(subcommand.stats, ["-f", "json", "-i", StringIO(query)])
        assert result.exit_code == 0
        assert result.output.strip("\n") == expected
        api_client.stats.assert_called_with(query=query)

    def test_no_query_passed(self, api_client):
        """Usage is returned if no query or input file is passed."""
        runner = CliRunner()

        result = runner.invoke(
            subcommand.stats, parent=Context(main, info_name="greynoise")
        )
        assert result.exit_code == -1
        assert "Usage: greynoise stats" in result.output
        api_client.stats.assert_not_called()

    def test_empty_input_file(self, api_client):
        """Error is returned if empty input fle is passed."""
        runner = CliRunner()

        expected = (
            "Error: at least one query must be passed either as an argument "
            "(QUERY) or through the -i/--input_file option."
        )

        result = runner.invoke(
            subcommand.stats,
            ["-i", StringIO()],
            parent=Context(main, info_name="greynoise"),
        )
        assert result.exit_code == -1
        assert "Usage: greynoise stats" in result.output
        assert expected in result.output
        api_client.query.assert_not_called()

    def test_request_failure(self, api_client):
        """Error is displayed on API request failure."""
        runner = CliRunner()

        api_client.stats.side_effect = RequestFailure(
            401, {"error": "forbidden", "status": "error"}
        )
        expected = "API error: forbidden"

        result = runner.invoke(subcommand.stats, ["<query>"])
        assert result.exit_code == -1
        assert expected in result.output

    def test_api_key_not_found(self):
        """Error is displayed if API key is not found."""
        runner = CliRunner()

        with patch("greynoise.cli.decorator.load_config") as load_config:
            load_config.return_value = {"api_key": ""}
            result = runner.invoke(
                subcommand.stats, ["query"], parent=Context(main, info_name="greynoise")
            )
            assert result.exit_code == -1
            assert "Error: API key not found" in result.output


class TestVersion(object):
    """Version subcommand test cases."""

    def test_not_implemented(self):
        """Not implemented error message returned."""
        runner = CliRunner()
        expected_output = "Error: 'version' subcommand is not implemented yet.\n"

        result = runner.invoke(subcommand.version)
        assert result.exit_code == 1
        assert result.output == expected_output
