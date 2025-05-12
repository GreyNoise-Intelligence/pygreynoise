# coding=utf-8
"""CLI subcommands test cases."""

import json
import textwrap
from collections import OrderedDict
from io import StringIO
from unittest.mock import patch

import pytest
from click import Context
from click.testing import CliRunner
from requests.exceptions import RequestException

from greynoise.__version__ import __version__
from greynoise.cli import main, subcommand
from greynoise.exceptions import RequestFailure
from greynoise.util import CONFIG_FILE, DEFAULT_CONFIG


@pytest.fixture
def api_client():
    load_config_patcher = patch("greynoise.cli.decorator.load_config")
    api_client_cls_patcher = patch("greynoise.cli.decorator.GreyNoise")
    with load_config_patcher as load_config:
        load_config.return_value = {
            "api_key": "<api_key>",
            "api_server": "<api_server>",
            "timeout": DEFAULT_CONFIG["timeout"],
            "offering": "enterprise",
        }
        with api_client_cls_patcher as api_client_cls:
            api_client = api_client_cls()
            yield api_client


class TestAccount(object):
    """Account subcommand test cases."""

    def test_not_implemented(self, api_client):
        """Not implemented error message returned."""
        runner = CliRunner()
        expected_output = "Error: 'account' subcommand is not implemented yet.\n"

        api_client.not_implemented.side_effect = RequestFailure(501)
        result = runner.invoke(subcommand.account)
        api_client.not_implemented.assert_called_with("account")
        assert result.exit_code == 1
        assert result.output == expected_output


class TestAlerts(object):
    """Alerts subcommand test cases."""

    def test_not_implemented(self, api_client):
        """Not implemented error message returned."""
        runner = CliRunner()
        expected_output = "Error: 'alerts' subcommand is not implemented yet.\n"

        api_client.not_implemented.side_effect = RequestFailure(501)
        result = runner.invoke(subcommand.alerts)
        api_client.not_implemented.assert_called_with("alerts")
        assert result.exit_code == 1
        assert result.output == expected_output


class TestAnalyze(object):
    """Analyze subcommand test cases."""

    DEFAULT_API_RESPONSE = {
        "query": ["<ip_address_1>", "<ip_address_2>"],
        "count": 0,
        "stats": {},
        "summary": {
            "ip_count": 0,
            "noise_ip_count": 0,
            "riot_ip_count": 0,
            "not_noise_ip_count": 0,
            "noise_ip_ratio": 0,
            "riot_ip_ratio": 0,
        },
    }
    DEFAULT_OUTPUT = textwrap.dedent(
        """\
        ╔═══════════════════════════╗
        ║          Analyze          ║
        ╚═══════════════════════════╝
        Summary:
        - IP count: 0
        - Noise IP count: 0
        - Not noise IP count: 0
        - RIOT IP count: 0
        - Noise IP ratio: 0.00
        - RIOT IP ratio: 0.00

        Queries:
        - <ip_address_1>
        - <ip_address_2>

        No results found for this query.
        """
    )

    @pytest.mark.parametrize(
        "expected_output",
        [
            (
                "Error: at least one text file must be passed "
                "either through the -i/--input_file option or through a shell pipe."
            ),
        ],
    )
    def test_no_input_file(self, api_client, expected_output):
        """No input text passed."""
        runner = CliRunner()

        api_client.analyze.return_value = expected_output

        with patch("greynoise.cli.subcommand.sys") as sys:
            sys.stdin.isatty.return_value = True
            result = runner.invoke(subcommand.analyze)
        assert result.exit_code == -1
        assert expected_output in result.output
        api_client.analyze.assert_not_called()

    @pytest.mark.parametrize("text", ["<input_text>"])
    def test_input_file(self, api_client, text):
        """Analyze text with IP addresses from file."""
        runner = CliRunner()

        input_text = StringIO(text)
        api_client.analyze.return_value = self.DEFAULT_API_RESPONSE

        result = runner.invoke(subcommand.analyze, ["-i", input_text])
        assert result.exit_code == 0
        assert result.output == self.DEFAULT_OUTPUT
        api_client.analyze.assert_called_with(input_text)

    @pytest.mark.parametrize("text", ["<input_text>"])
    def test_stdin_input(self, api_client, text):
        """Analyze text with IP addresses from stdin."""
        runner = CliRunner()

        api_client.analyze.return_value = self.DEFAULT_API_RESPONSE

        result = runner.invoke(subcommand.analyze, input=text)
        assert result.exit_code == 0
        assert result.output == self.DEFAULT_OUTPUT
        assert api_client.analyze.call_args[0][0].read() == text

    @pytest.mark.parametrize("text", ["<input_text>"])
    def test_explicit_stdin_input(self, api_client, text):
        """Analyze text with IP addresses from stdin passed explicitly."""
        runner = CliRunner()

        api_client.analyze.return_value = self.DEFAULT_API_RESPONSE

        result = runner.invoke(subcommand.analyze, ["-i", "-"], input=text)
        assert result.exit_code == 0
        assert result.output == self.DEFAULT_OUTPUT
        assert api_client.analyze.call_args[0][0].read() == text

    def test_requests_exception(self, api_client, caplog):
        """Error is displayed on requests library exception."""
        runner = CliRunner()
        expected = "API error: <error message>"

        api_client.analyze.side_effect = RequestException("<error message>")
        result = runner.invoke(subcommand.analyze, input="some text")
        assert result.exit_code == -1
        assert caplog.records[0].message == expected

    def test_api_key_not_found(self):
        """Error is displayed if API key is not found."""
        runner = CliRunner()

        with patch("greynoise.cli.decorator.load_config") as load_config:
            load_config.return_value = {"api_key": ""}
            result = runner.invoke(
                subcommand.analyze,
                input="some text",
                parent=Context(main, info_name="greynoise"),
            )
            assert result.exit_code == -1
            assert "Error: API key not found" in result.output


class TestFeedback(object):
    """Feedback subcommand test cases."""

    def test_not_implemented(self, api_client):
        """Not implemented error message returned."""
        runner = CliRunner()
        expected_output = "Error: 'feedback' subcommand is not implemented yet.\n"

        api_client.not_implemented.side_effect = RequestFailure(501)
        result = runner.invoke(subcommand.feedback)
        api_client.not_implemented.assert_called_with("feedback")
        assert result.exit_code == 1
        assert result.output == expected_output


class TestFilter(object):
    """Filter subcommand test cases."""

    @pytest.mark.parametrize(
        "expected_output",
        [
            (
                "Error: at least one text file must be passed "
                "either through the -i/--input_file option or through a shell pipe."
            ),
        ],
    )
    def test_no_input_file(self, api_client, expected_output):
        """No input text passed."""
        runner = CliRunner()

        api_client.filter.return_value = expected_output

        with patch("greynoise.cli.subcommand.sys") as sys:
            sys.stdin.isatty.return_value = True
            result = runner.invoke(subcommand.filter)
        assert result.exit_code == -1
        assert expected_output in result.output
        api_client.filter.assert_not_called()

    @pytest.mark.parametrize(
        "text, expected_output",
        [
            ("<input_text>", "<output_text>"),
            ("<input_text>", ("<chunk_1>\n", "<chunk_2>\n")),
        ],
    )
    def test_input_file(self, api_client, text, expected_output):
        """Filter text with IP addresses from file."""
        runner = CliRunner()

        input_text = StringIO(text)
        api_client.filter.return_value = expected_output

        result = runner.invoke(subcommand.filter, ["-i", input_text])
        assert result.exit_code == 0
        assert result.output == "".join(expected_output)
        api_client.filter.assert_called_with(
            input_text, noise_only=False, riot_only=False
        )

    @pytest.mark.parametrize(
        "text, expected_output",
        [
            ("<input_text>", "<output_text>"),
            ("<input_text>", ("<chunk_1>\n", "<chunk_2>\n")),
        ],
    )
    def test_stdin_input(self, api_client, text, expected_output):
        """Filter text with IP addresses from stdin."""
        runner = CliRunner()

        api_client.filter.return_value = expected_output

        result = runner.invoke(subcommand.filter, input=text)
        assert result.exit_code == 0
        assert result.output == "".join(expected_output)
        assert api_client.filter.call_args[0][0].read() == text
        assert api_client.filter.call_args[1] == {
            "noise_only": False,
            "riot_only": False,
        }

    @pytest.mark.parametrize(
        "text, expected_output",
        [
            ("<input_text>", "<output_text>"),
            ("<input_text>", ("<chunk_1>\n", "<chunk_2>\n")),
        ],
    )
    def test_noise_only(self, api_client, text, expected_output):
        """Filter text with IP addresses from stdin using noise only flag."""
        runner = CliRunner()

        api_client.filter.return_value = expected_output

        result = runner.invoke(subcommand.filter, ["--noise-only"], input=text)
        assert result.exit_code == 0
        assert result.output == "".join(expected_output)
        assert api_client.filter.call_args[0][0].read() == text
        assert api_client.filter.call_args[1] == {
            "noise_only": True,
            "riot_only": False,
        }

    @pytest.mark.parametrize(
        "text, expected_output",
        [
            ("<input_text>", "<output_text>"),
            ("<input_text>", ("<chunk_1>\n", "<chunk_2>\n")),
        ],
    )
    def test_riot_only(self, api_client, text, expected_output):
        """Filter text with IP addresses from stdin using riot only flag."""
        runner = CliRunner()

        api_client.filter.return_value = expected_output

        result = runner.invoke(subcommand.filter, ["--riot-only"], input=text)
        assert result.exit_code == 0
        assert result.output == "".join(expected_output)
        assert api_client.filter.call_args[0][0].read() == text
        assert api_client.filter.call_args[1] == {
            "noise_only": False,
            "riot_only": True,
        }

    @pytest.mark.parametrize(
        "text, expected_output",
        [
            ("<input_text>", "<output_text>"),
            ("<input_text>", ("<chunk_1>\n", "<chunk_2>\n")),
        ],
    )
    def test_explicit_stdin_input(self, api_client, text, expected_output):
        """Filter text with IP addresses from stdin passed explicitly."""
        runner = CliRunner()

        api_client.filter.return_value = expected_output

        result = runner.invoke(subcommand.filter, ["-i", "-"], input=text)
        assert result.exit_code == 0
        assert result.output == "".join(expected_output)
        assert api_client.filter.call_args[0][0].read() == text
        assert api_client.filter.call_args[1] == {
            "noise_only": False,
            "riot_only": False,
        }

    def test_request_failure(self, api_client, caplog):
        """Error is displayed on API request failure."""
        runner = CliRunner()

        api_client.filter.side_effect = RequestFailure(
            401, {"message": "forbidden", "status": "error"}
        )
        expected = "API error: forbidden"

        result = runner.invoke(subcommand.filter, input="some text")
        assert result.exit_code == -1
        assert caplog.records[0].message == expected

    def test_requests_exception(self, api_client, caplog):
        """Error is displayed on requests library exception."""
        runner = CliRunner()
        expected = "API error: <error message>"

        api_client.filter.side_effect = RequestException("<error message>")
        result = runner.invoke(subcommand.filter, input="some text")
        assert result.exit_code == -1
        assert caplog.records[0].message == expected

    def test_api_key_not_found(self):
        """Error is displayed if API key is not found."""
        runner = CliRunner()

        with patch("greynoise.cli.decorator.load_config") as load_config:
            load_config.return_value = {"api_key": ""}
            result = runner.invoke(
                subcommand.filter,
                input="some text",
                parent=Context(main, info_name="greynoise"),
            )
            assert result.exit_code == -1
            assert "Error: API key not found" in result.output


class TestHelp(object):
    """Help subcommand test cases."""

    def test_help(self):
        """Get help."""
        runner = CliRunner()
        expected_output = "Usage: greynoise [OPTIONS] COMMAND [ARGS]..."

        result = runner.invoke(
            subcommand.help_, parent=Context(main, info_name="greynoise")
        )
        assert result.exit_code == 0
        assert expected_output in result.output


class TestIP(object):
    """IP subcommand tests."""

    @pytest.mark.parametrize("ip_address, expected_response", [("8.8.8.8", {})])
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

    @pytest.mark.parametrize("ip_address, expected_response", [("8.8.8.8", {})])
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

    @pytest.mark.parametrize("ip_address, expected_response", [("8.8.8.8", {})])
    def test_stdin_input(self, api_client, ip_address, expected_response):
        """Get IP address information from stdin."""
        runner = CliRunner()

        api_client.ip.return_value = expected_response

        result = runner.invoke(subcommand.ip, ["-f", "json"], input=ip_address)
        assert result.exit_code == 0
        assert result.output.strip("\n") == json.dumps(
            [expected_response], indent=4, sort_keys=True
        )
        api_client.ip.assert_called_with(ip_address=ip_address)

    def test_no_ip_address_passed(self, api_client):
        """Usage is returned if no IP address or input file is passed."""
        runner = CliRunner()

        with patch("greynoise.cli.helper.sys") as sys:
            sys.stdin.isatty.return_value = True
            result = runner.invoke(
                subcommand.ip, parent=Context(main, info_name="greynoise")
            )
        assert result.exit_code == -1
        assert "Usage: greynoise ip" in result.output
        api_client.ip.assert_not_called()

    def test_input_file_invalid_ip_addresses_passed(self, api_client):
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

        expected = "Error: Invalid value for '[IP_ADDRESS]...': not-an-ip\n"

        result = runner.invoke(subcommand.ip, ["not-an-ip"])
        assert result.exit_code == 2
        assert "Usage: ip [OPTIONS] [IP_ADDRESS]..." in result.output
        assert expected in result.output
        api_client.ip.assert_not_called()

    def test_request_failure(self, api_client, caplog):
        """Error is displayed on API request failure."""
        runner = CliRunner()

        api_client.ip.side_effect = RequestFailure(
            401, {"message": "forbidden", "status": "error"}
        )
        expected = "API error: forbidden"

        result = runner.invoke(subcommand.ip, ["8.8.8.8"])
        assert result.exit_code == -1
        assert caplog.records[0].message == expected

    def test_requests_exception(self, api_client, caplog):
        """Error is displayed on requests library exception."""
        runner = CliRunner()
        expected = "API error: <error message>"

        api_client.ip.side_effect = RequestException("<error message>")
        result = runner.invoke(subcommand.ip, ["8.8.8.8"])
        assert result.exit_code == -1
        assert caplog.records[0].message == expected

    def test_api_key_not_found(self):
        """Error is displayed if API key is not found."""
        runner = CliRunner()

        with patch("greynoise.cli.decorator.load_config") as load_config:
            load_config.return_value = {"api_key": ""}
            result = runner.invoke(
                subcommand.ip, ["8.8.8.8"], parent=Context(main, info_name="greynoise")
            )
            assert result.exit_code == -1
            assert "Error: API key not found" in result.output


class TestSensorActivity(object):
    """Sensor Activity subcommand tests."""

    def test_sensor_activity(self, api_client):
        """Run sensor activity."""
        runner = CliRunner()

        workspace_id = "workspace_id"
        api_client.sensor_activity.return_value = {}
        expected = "{}"

        result = runner.invoke(subcommand.sensor_activity, ["-f", "json", workspace_id])

        assert result.exit_code == 0
        assert result.output.strip("\n") == expected
        api_client.sensor_activity.assert_called_with(
            workspace_id=workspace_id,
            file_format="json",
            start_time=None,
            end_time=None,
            persona_id=None,
            source_ip=None,
            size=None,
            scroll=None,
        )

    def test_request_failure(self, api_client, caplog):
        """Error is displayed on API request failure."""
        runner = CliRunner()

        workspace_id = "workspace_id"
        api_client.sensor_activity.side_effect = RequestFailure(
            401, {"message": "forbidden", "status": "error"}
        )
        expected = "API error: forbidden"

        result = runner.invoke(subcommand.sensor_activity, ["-f", "json", workspace_id])
        assert result.exit_code == -1
        assert caplog.records[0].message == expected

    def test_api_key_not_found(self):
        """Error is displayed if API key is not found."""
        runner = CliRunner()

        workspace_id = "workspace_id"

        with patch("greynoise.cli.decorator.load_config") as load_config:
            load_config.return_value = {"api_key": ""}
            result = runner.invoke(
                subcommand.sensor_activity,
                ["-f", "json", workspace_id],
                parent=Context(main, info_name="greynoise"),
            )
            assert result.exit_code == -1
            assert "Error: API key not found" in result.output


class TestQuery(object):
    """Query subcommand tests."""

    def test_query(self, api_client):
        """Run query."""
        runner = CliRunner()

        query = "<query>"
        api_client.query.return_value = []
        expected = json.dumps([[]], indent=4, sort_keys=True)

        result = runner.invoke(subcommand.query, ["-f", "json", query])
        assert result.exit_code == 0
        assert result.output.strip("\n") == expected
        api_client.query.assert_called_with(query=query, size=None, scroll=None)

    def test_input_file(self, api_client):
        """Run query from input file."""
        runner = CliRunner()

        query = "<query>"
        api_client.query.return_value = []
        expected = json.dumps([[]], indent=4, sort_keys=True)

        result = runner.invoke(subcommand.query, ["-f", "json", "-i", StringIO(query)])
        assert result.exit_code == 0
        assert result.output.strip("\n") == expected
        api_client.query.assert_called_with(query=query, size=None, scroll=None)

    def test_stdin_input(self, api_client):
        """Run query from stdin."""
        runner = CliRunner()

        query = "<query>"
        api_client.query.return_value = []
        expected = json.dumps([[]], indent=4, sort_keys=True)

        result = runner.invoke(subcommand.query, ["-f", "json"], input=query)
        assert result.exit_code == 0
        assert result.output.strip("\n") == expected
        api_client.query.assert_called_with(query=query, size=None, scroll=None)

    def test_no_query_passed(self, api_client):
        """Usage is returned if no query or input file is passed."""
        runner = CliRunner()

        with patch("greynoise.cli.helper.sys") as sys:
            sys.stdin.isatty.return_value = True
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

    def test_request_failure(self, api_client, caplog):
        """Error is displayed on API request failure."""
        runner = CliRunner()

        api_client.query.side_effect = RequestFailure(
            401, {"message": "forbidden", "status": "error"}
        )
        expected = "API error: forbidden"

        result = runner.invoke(subcommand.query, ["<query>"])
        assert result.exit_code == -1
        assert caplog.records[0].message == expected

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
                "8.8.8.8",
                "json",
                json.dumps(
                    [
                        {
                            "ip": "8.8.8.8",
                            "internet_scanner_intelligence": {
                                "found": True,
                                "classification": "malicious",
                            },
                            "business_service_intelligence": {
                                "found": True,
                                "trust_level": "1",
                            },
                        }
                    ],
                    indent=4,
                    sort_keys=True,
                ),
            ),
            (
                "8.8.8.8",
                "xml",
                textwrap.dedent(
                    """\
                    <?xml version="1.0" ?>
                    <root>
                    \t<item>
                    \t\t<ip>8.8.8.8</ip>
                    \t\t<internet_scanner_intelligence>
                    \t\t\t<classification>malicious</classification>
                    \t\t\t<found>True</found>
                    \t\t</internet_scanner_intelligence>
                    \t\t<business_service_intelligence>
                    \t\t\t<found>True</found>
                    \t\t\t<trust_level>1</trust_level>
                    \t\t</business_service_intelligence>
                    \t</item>
                    </root>"""
                ),
            ),
            (
                "8.8.8.8",
                "txt",
                "8.8.8.8 is identified as NOISE, is classified as "
                "malicious and is part of RIOT and is Trust Level 1.",
            ),
        ),
    )
    def test_quick(self, api_client, ip_address, output_format, expected):
        """Quickly check IP address."""
        runner = CliRunner()

        api_client.quick.return_value = [
            OrderedDict(
                [
                    ("ip", ip_address),
                    (
                        "internet_scanner_intelligence",
                        {"found": True, "classification": "malicious"},
                    ),
                    (
                        "business_service_intelligence",
                        {"found": True, "trust_level": "1"},
                    ),
                ]
            )
        ]

        result = runner.invoke(subcommand.quick, ["-f", output_format, ip_address])
        assert result.exit_code == 0
        assert result.output.strip("\n") == expected
        api_client.quick.assert_called_with(ip_addresses=[ip_address])

    @pytest.mark.parametrize(
        "ip_addresses, mock_response, expected",
        (
            (
                ["8.8.8.8", "8.8.8.9"],
                [
                    OrderedDict([("ip", "8.8.8.8"), ("noise", True)]),
                    OrderedDict([("ip", "8.8.8.9"), ("noise", False)]),
                ],
                json.dumps(
                    [
                        {"ip": "8.8.8.8", "noise": True},
                        {"ip": "8.8.8.9", "noise": False},
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

    @pytest.mark.parametrize(
        "ip_addresses, mock_response, expected",
        (
            (
                ["8.8.8.8", "8.8.8.9"],
                [
                    OrderedDict([("ip", "8.8.8.8"), ("noise", True)]),
                    OrderedDict([("ip", "8.8.8.9"), ("noise", False)]),
                ],
                json.dumps(
                    [
                        {"ip": "8.8.8.8", "noise": True},
                        {"ip": "8.8.8.9", "noise": False},
                    ],
                    indent=4,
                    sort_keys=True,
                ),
            ),
        ),
    )
    def test_stdin_input(self, api_client, ip_addresses, mock_response, expected):
        """Quickly check IP address from stdin."""
        runner = CliRunner()

        api_client.quick.return_value = mock_response

        result = runner.invoke(
            subcommand.quick, ["-f", "json"], input="\n".join(ip_addresses)
        )
        assert result.exit_code == 0
        assert result.output.strip("\n") == expected
        api_client.quick.assert_called_with(ip_addresses=ip_addresses)

    def test_no_ip_address_passed(self, api_client):
        """Usage is returned if no IP address or input file is passed."""
        runner = CliRunner()

        with patch("greynoise.cli.helper.sys") as sys:
            sys.stdin.isatty.return_value = True
            result = runner.invoke(
                subcommand.quick, parent=Context(main, info_name="greynoise")
            )
        assert result.exit_code == -1
        assert "Usage: greynoise quick" in result.output
        api_client.quick.assert_not_called()

    def test_input_file_invalid_ip_addresses_passed(self, api_client):
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

        expected = "Error: Invalid value for '[IP_ADDRESS]...': not-an-ip\n"

        result = runner.invoke(subcommand.quick, ["not-an-ip"])
        assert result.exit_code == 2
        assert "Usage: quick [OPTIONS] [IP_ADDRESS]..." in result.output
        assert expected in result.output
        api_client.quick.assert_not_called()

    def test_request_failure(self, api_client, caplog):
        """Error is displayed on API request failure."""
        runner = CliRunner()

        api_client.quick.side_effect = RequestFailure(
            401, {"message": "forbidden", "status": "error"}
        )
        expected = "API error: forbidden"

        result = runner.invoke(subcommand.quick, ["8.8.8.8"])
        assert result.exit_code == -1
        assert caplog.records[0].message == expected

    def test_api_key_not_found(self):
        """Error is displayed if API key is not found."""
        runner = CliRunner()

        with patch("greynoise.cli.decorator.load_config") as load_config:
            load_config.return_value = {"api_key": ""}
            result = runner.invoke(
                subcommand.quick,
                ["8.8.8.8"],
                parent=Context(main, info_name="greynoise"),
            )
            assert result.exit_code == -1
            assert "Error: API key not found" in result.output


class TestIPMulti(object):
    """IP-Multi subcommand tests."""

    @pytest.mark.parametrize(
        "ip_address, output_format, expected",
        (
            (
                "8.8.8.8",
                "json",
                json.dumps(
                    [
                        {
                            "ip": "8.8.8.8",
                            "internet_scanner_intelligence": {"found": False},
                            "business_service_intelligence": {"found": False},
                        }
                    ],
                    indent=4,
                    sort_keys=True,
                ),
            ),
            (
                "8.8.8.8",
                "xml",
                textwrap.dedent(
                    """\
                    <?xml version="1.0" ?>
                    <root>
                    \t<item>
                    \t\t<ip>8.8.8.8</ip>
                    \t\t<internet_scanner_intelligence>
                    \t\t\t<found>False</found>
                    \t\t</internet_scanner_intelligence>
                    \t\t<business_service_intelligence>
                    \t\t\t<found>False</found>
                    \t\t</business_service_intelligence>
                    \t</item>
                    </root>"""
                ),
            ),
            (
                "8.8.8.8",
                "txt",
                "╔═══════════════════════════╗\n"
                "║      Context 1 of 1       ║\n"
                "╚═══════════════════════════╝\n"
                "IP address: 8.8.8.8\n\n"
                "8.8.8.8 has not been seen in scans in the past 90 days.",
            ),
        ),
    )
    def test_ip_multi(self, api_client, ip_address, output_format, expected):
        """Quickly check IP address."""
        runner = CliRunner()

        api_client.ip_multi.return_value = [
            OrderedDict(
                (
                    ("ip", ip_address),
                    ("internet_scanner_intelligence", {"found": False}),
                    ("business_service_intelligence", {"found": False}),
                )
            )
        ]

        result = runner.invoke(subcommand.ip_multi, ["-f", output_format, ip_address])
        assert result.exit_code == 0
        assert result.output.strip("\n") == expected
        api_client.ip_multi.assert_called_with(ip_addresses=[ip_address])

    @pytest.mark.parametrize(
        "ip_addresses, mock_response, expected",
        (
            (
                ["8.8.8.8", "8.8.8.9"],
                [
                    OrderedDict(
                        [
                            ("ip", "8.8.8.8"),
                            ("internet_scanner_intelligence", {"found": False}),
                        ]
                    ),
                    OrderedDict(
                        [
                            ("ip", "8.8.8.9"),
                            ("internet_scanner_intelligence", {"found": False}),
                        ]
                    ),
                ],
                json.dumps(
                    [
                        {
                            "ip": "8.8.8.8",
                            "internet_scanner_intelligence": {"found": False},
                        },
                        {
                            "ip": "8.8.8.9",
                            "internet_scanner_intelligence": {"found": False},
                        },
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

        api_client.ip_multi.return_value = mock_response

        result = runner.invoke(
            subcommand.ip_multi, ["-f", "json", "-i", StringIO("\n".join(ip_addresses))]
        )
        assert result.exit_code == 0
        assert result.output.strip("\n") == expected
        api_client.ip_multi.assert_called_with(ip_addresses=ip_addresses)

    @pytest.mark.parametrize(
        "ip_addresses, mock_response, expected",
        (
            (
                ["8.8.8.8", "8.8.8.9"],
                [
                    OrderedDict([("ip", "8.8.8.8"), ("noise", True)]),
                    OrderedDict([("ip", "8.8.8.9"), ("noise", False)]),
                ],
                json.dumps(
                    [
                        {"ip": "8.8.8.8", "noise": True},
                        {"ip": "8.8.8.9", "noise": False},
                    ],
                    indent=4,
                    sort_keys=True,
                ),
            ),
        ),
    )
    def test_stdin_input(self, api_client, ip_addresses, mock_response, expected):
        """Quickly check IP address from stdin."""
        runner = CliRunner()

        api_client.ip_multi.return_value = mock_response

        result = runner.invoke(
            subcommand.ip_multi, ["-f", "json"], input="\n".join(ip_addresses)
        )
        assert result.exit_code == 0
        assert result.output.strip("\n") == expected
        api_client.ip_multi.assert_called_with(ip_addresses=ip_addresses)

    def test_no_ip_address_passed(self, api_client):
        """Usage is returned if no IP address or input file is passed."""
        runner = CliRunner()

        with patch("greynoise.cli.helper.sys") as sys:
            sys.stdin.isatty.return_value = True
            result = runner.invoke(
                subcommand.ip_multi, parent=Context(main, info_name="greynoise")
            )
        assert result.exit_code == -1
        assert "Usage: greynoise ip-multi" in result.output
        api_client.ip_multi.assert_not_called()

    def test_input_file_invalid_ip_addresses_passed(self, api_client):
        """Error returned if only invalid IP addresses are passed in input file."""
        runner = CliRunner()

        expected = (
            "Error: at least one valid IP address must be passed either as an "
            "argument (IP_ADDRESS) or through the -i/--input_file option."
        )

        result = runner.invoke(
            subcommand.ip_multi,
            ["-i", StringIO("not-an-ip")],
            parent=Context(main, info_name="greynoise"),
        )
        assert result.exit_code == -1
        assert "Usage: greynoise ip-multi" in result.output
        assert expected in result.output
        api_client.ip_multi.assert_not_called()

    def test_invalid_ip_address_as_argument(self, api_client):
        """Quick subcommand fails when ip_address is invalid."""
        runner = CliRunner()

        expected = "Error: Invalid value for '[IP_ADDRESS]...': not-an-ip\n"

        result = runner.invoke(subcommand.ip_multi, ["not-an-ip"])
        assert result.exit_code == 2
        assert "Usage: ip-multi [OPTIONS] [IP_ADDRESS]..." in result.output
        assert expected in result.output
        api_client.ip_multi.assert_not_called()

    def test_request_failure(self, api_client, caplog):
        """Error is displayed on API request failure."""
        runner = CliRunner()

        api_client.ip_multi.side_effect = RequestFailure(
            401, {"message": "forbidden", "status": "error"}
        )
        expected = "API error: forbidden"

        result = runner.invoke(subcommand.ip_multi, ["8.8.8.8"])
        assert result.exit_code == -1
        assert caplog.records[0].message == expected

    def test_api_key_not_found(self):
        """Error is displayed if API key is not found."""
        runner = CliRunner()

        with patch("greynoise.cli.decorator.load_config") as load_config:
            load_config.return_value = {"api_key": ""}
            result = runner.invoke(
                subcommand.ip_multi,
                ["8.8.8.8"],
                parent=Context(main, info_name="greynoise"),
            )
            assert result.exit_code == -1
            assert "Error: API key not found" in result.output


class TestSignature(object):
    """Signature subcommand test cases."""

    def test_not_implemented(self, api_client):
        """Not implemented error message returned."""
        runner = CliRunner()
        expected_output = "Error: 'signature' subcommand is not implemented yet.\n"

        api_client.not_implemented.side_effect = RequestFailure(501)
        result = runner.invoke(subcommand.signature)
        api_client.not_implemented.assert_called_with("signature")
        assert result.exit_code == 1
        assert result.output == expected_output


class TestSetup(object):
    """Setup subcommand test cases."""

    @pytest.mark.parametrize("key_option", ["-k", "--api-key"])
    def test_save_api_key(self, key_option):
        """Save API key to configuration file."""
        runner = CliRunner()
        api_key = "<api_key>"
        expected_config = {
            "api_key": api_key,
            "api_server": DEFAULT_CONFIG["api_server"],
            "timeout": DEFAULT_CONFIG["timeout"],
            "proxy": DEFAULT_CONFIG["proxy"],
            "offering": DEFAULT_CONFIG["offering"],
        }
        expected_output = "Configuration saved in {}.\n".format(CONFIG_FILE)

        with patch("greynoise.cli.subcommand.save_config") as save_config:
            result = runner.invoke(subcommand.setup, [key_option, api_key])
        assert result.exit_code == 0
        assert result.output == expected_output
        save_config.assert_called_with(expected_config)

    @pytest.mark.parametrize("key_option", ["-k", "--api-key"])
    @pytest.mark.parametrize("server_option", ["-s", "--api-server"])
    @pytest.mark.parametrize("timeout_option", ["-t", "--timeout"])
    @pytest.mark.parametrize("proxy_option", ["-p", "--proxy"])
    @pytest.mark.parametrize("offering_option", ["-O", "--offering"])
    def test_save_api_key_and_timeout(
        self, key_option, server_option, timeout_option, proxy_option, offering_option
    ):
        """Save API key and timeout to configuration file."""
        runner = CliRunner()
        api_key = "<api_key>"
        api_server = "<api_server>"
        timeout = 123456
        proxy = "<proxy>"
        offering = "<offering>"
        expected_config = {
            "api_key": api_key,
            "api_server": api_server,
            "timeout": timeout,
            "proxy": proxy,
            "offering": offering,
        }
        expected_output = "Configuration saved in {}.\n".format(CONFIG_FILE)

        with patch("greynoise.cli.subcommand.save_config") as save_config:
            result = runner.invoke(
                subcommand.setup,
                [
                    key_option,
                    api_key,
                    server_option,
                    api_server,
                    timeout_option,
                    timeout,
                    proxy_option,
                    proxy,
                    offering_option,
                    offering,
                ],
            )
        assert result.exit_code == 0
        assert result.output == expected_output
        save_config.assert_called_with(expected_config)

    def test_missing_api_key(self):
        """Setup fails when api_key is not passed."""
        runner = CliRunner()
        expected_error = "Error: Missing option '-k' / '--api-key'"

        result = runner.invoke(subcommand.setup, [])
        assert result.exit_code == 2
        assert "setup [OPTIONS]\nTry 'setup --help' for help." in result.output
        assert expected_error in result.output


class TestStats(object):
    """Stats subcommand tests."""

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

    def test_stdin_input(self, api_client):
        """Run stats query from input file."""
        runner = CliRunner()

        query = "<query>"
        api_client.stats.return_value = []
        expected = json.dumps([[]], indent=4, sort_keys=True)

        result = runner.invoke(subcommand.stats, ["-f", "json"], input=query)
        assert result.exit_code == 0
        assert result.output.strip("\n") == expected
        api_client.stats.assert_called_with(query=query)

    def test_no_query_passed(self, api_client):
        """Usage is returned if no query or input file is passed."""
        runner = CliRunner()

        with patch("greynoise.cli.helper.sys") as sys:
            sys.stdin.isatty.return_value = True
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

    def test_request_failure(self, api_client, caplog):
        """Error is displayed on API request failure."""
        runner = CliRunner()

        api_client.stats.side_effect = RequestFailure(
            401, {"message": "forbidden", "status": "error"}
        )
        expected = "API error: forbidden"

        result = runner.invoke(subcommand.stats, ["-f", "json", "some query"])
        assert result.exit_code == -1
        assert caplog.records[0].message == expected

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

    def test_version(self):
        """Version returned."""
        runner = CliRunner()
        expected_output = "greynoise {}".format(__version__)

        result = runner.invoke(subcommand.version)
        assert result.exit_code == 0
        assert result.output.startswith(expected_output)


class TestSimilar(object):
    """Similar subcommand tests."""

    DEFAULT_SIM_RESPONSE = {
        "ip": {
            "actor": "Alpha Strike Labs",
            "asn": "AS208843",
            "city": "Berlin",
            "classification": "benign",
            "country": "Germany",
            "country_code": "DE",
            "first_seen": "2019-07-12",
            "ip": "45.83.66.65",
            "last_seen": "2022-12-19",
            "organization": "Alpha Strike Labs GmbH",
        },
        "similar_ips": [
            {
                "actor": "Alpha Strike Labs",
                "asn": "AS208843",
                "city": "Berlin",
                "classification": "benign",
                "country": "Germany",
                "country_code": "DE",
                "features": [
                    "ja3_fp",
                    "mass_scan_bool",
                    "os",
                    "ports",
                    "useragents",
                    "web_paths",
                ],
                "first_seen": "2019-07-31",
                "ip": "45.83.66.255",
                "last_seen": "2022-12-19",
                "organization": "Alpha Strike Labs GmbH",
                "score": 0.96865726,
            }
        ],
        "total": 1119,
    }

    @pytest.mark.parametrize(
        "ip_address, output_format, expected",
        (
            (
                "45.83.66.65",
                "json",
                json.dumps([DEFAULT_SIM_RESPONSE], indent=4, sort_keys=True),
            ),
            (
                "45.83.66.65",
                "xml",
                textwrap.dedent(
                    """\
                    <?xml version="1.0" ?>
                    <root>
                    \t<item>
                    \t\t<ip>
                    \t\t\t<actor>Alpha Strike Labs</actor>
                    \t\t\t<asn>AS208843</asn>
                    \t\t\t<city>Berlin</city>
                    \t\t\t<classification>benign</classification>
                    \t\t\t<country>Germany</country>
                    \t\t\t<country_code>DE</country_code>
                    \t\t\t<first_seen>2019-07-12</first_seen>
                    \t\t\t<ip>45.83.66.65</ip>
                    \t\t\t<last_seen>2022-12-19</last_seen>
                    \t\t\t<organization>Alpha Strike Labs GmbH</organization>
                    \t\t</ip>
                    \t\t<similar_ips>
                    \t\t\t<actor>Alpha Strike Labs</actor>
                    \t\t\t<asn>AS208843</asn>
                    \t\t\t<city>Berlin</city>
                    \t\t\t<classification>benign</classification>
                    \t\t\t<country>Germany</country>
                    \t\t\t<country_code>DE</country_code>
                    \t\t\t<features>ja3_fp</features>
                    \t\t\t<features>mass_scan_bool</features>
                    \t\t\t<features>os</features>
                    \t\t\t<features>ports</features>
                    \t\t\t<features>useragents</features>
                    \t\t\t<features>web_paths</features>
                    \t\t\t<first_seen>2019-07-31</first_seen>
                    \t\t\t<ip>45.83.66.255</ip>
                    \t\t\t<last_seen>2022-12-19</last_seen>
                    \t\t\t<organization>Alpha Strike Labs GmbH</organization>
                    \t\t\t<score>0.96865726</score>
                    \t\t</similar_ips>
                    \t\t<total>1119</total>
                    \t</item>
                    </root>"""
                ),
            ),
        ),
    )
    def test_similar(self, api_client, ip_address, output_format, expected):
        """Quickly check IP address for similar IPs"""
        runner = CliRunner()

        api_client.similar.return_value = self.DEFAULT_SIM_RESPONSE

        result = runner.invoke(subcommand.similar, ["-f", output_format, ip_address])
        assert result.exit_code == 0
        assert result.output.strip("\n") == expected
        api_client.similar.assert_called_with(
            ip_address=ip_address, limit=None, min_score=None
        )

    @pytest.mark.parametrize(
        "ip_address, mock_response, expected",
        (
            (
                "45.83.66.65",
                DEFAULT_SIM_RESPONSE,
                DEFAULT_SIM_RESPONSE,
            ),
        ),
    )
    def test_input_file(self, api_client, ip_address, mock_response, expected):
        """Get IP address information from input file."""
        runner = CliRunner()

        api_client.similar.return_value = expected

        result = runner.invoke(
            subcommand.similar, ["-f", "json", "-i", StringIO(ip_address)]
        )
        assert result.exit_code == 0
        assert result.output.strip("\n") == json.dumps(
            [expected], indent=4, sort_keys=True
        )
        api_client.similar.assert_called_with(
            ip_address=ip_address, limit=None, min_score=None
        )

    @pytest.mark.parametrize(
        "ip_address, mock_response, expected",
        (
            (
                "45.83.66.65",
                DEFAULT_SIM_RESPONSE,
                DEFAULT_SIM_RESPONSE,
            ),
        ),
    )
    def test_stdin_input(self, api_client, ip_address, mock_response, expected):
        """Quickly check IP address from stdin."""
        runner = CliRunner()

        api_client.similar.return_value = mock_response

        result = runner.invoke(subcommand.similar, ["-f", "json"], input=ip_address)
        assert result.exit_code == 0
        assert result.output.strip("\n") == json.dumps(
            [expected], indent=4, sort_keys=True
        )
        api_client.similar.assert_called_with(
            ip_address=ip_address, limit=None, min_score=None
        )

    def test_no_ip_address_passed(self, api_client):
        """Usage is returned if no IP address or input file is passed."""
        runner = CliRunner()

        with patch("greynoise.cli.helper.sys") as sys:
            sys.stdin.isatty.return_value = True
            result = runner.invoke(
                subcommand.similar, parent=Context(main, info_name="greynoise")
            )
        assert result.exit_code == -1
        assert "Usage: greynoise similar" in result.output
        api_client.similar.assert_not_called()

    def test_input_file_invalid_ip_addresses_passed(self, api_client):
        """Error returned if only invalid IP addresses are passed in input file."""
        runner = CliRunner()

        expected = (
            "Error: at least one valid IP address must be passed either as an "
            "argument (IP_ADDRESS) or through the -i/--input_file option."
        )

        result = runner.invoke(
            subcommand.similar,
            ["-i", StringIO("not-an-ip")],
            parent=Context(main, info_name="greynoise"),
        )
        assert result.exit_code == -1
        assert "Usage: greynoise similar" in result.output
        assert expected in result.output
        api_client.similar.assert_not_called()

    def test_invalid_ip_address_as_argument(self, api_client):
        """Quick subcommand fails when ip_address is invalid."""
        runner = CliRunner()

        expected = "Error: Invalid value for '[IP_ADDRESS]...': not-an-ip\n"

        result = runner.invoke(subcommand.similar, ["not-an-ip"])
        assert result.exit_code == 2
        assert "Usage: similar [OPTIONS] [IP_ADDRESS]..." in result.output
        assert expected in result.output
        api_client.similar.assert_not_called()

    def test_request_failure(self, api_client, caplog):
        """Error is displayed on API request failure."""
        runner = CliRunner()

        api_client.similar.side_effect = RequestFailure(
            401, {"message": "forbidden", "status": "error"}
        )
        expected = "API error: forbidden"

        result = runner.invoke(subcommand.similar, ["8.8.8.8"])
        assert result.exit_code == -1
        assert caplog.records[0].message == expected

    def test_api_key_not_found(self):
        """Error is displayed if API key is not found."""
        runner = CliRunner()

        with patch("greynoise.cli.decorator.load_config") as load_config:
            load_config.return_value = {"api_key": ""}
            result = runner.invoke(
                subcommand.similar,
                ["8.8.8.8"],
                parent=Context(main, info_name="greynoise"),
            )
            assert result.exit_code == -1
            assert "Error: API key not found" in result.output


class TestTimeline(object):
    """Timeline subcommand tests."""

    DEFAULT_TIMELINE_RESPONSE = {
        "ip": "45.83.66.65",
        "metadata": {
            "end": "2023-01-09T15:52:21.797662573Z",
            "field": "classification",
            "granularity": "1d",
            "ip": "45.83.66.65",
            "metric": "count",
            "start": "2023-01-08T00:00:00Z",
        },
        "results": [],
    }

    @pytest.mark.parametrize(
        "ip_address, output_format, expected",
        (
            (
                "45.83.66.65",
                "json",
                json.dumps([DEFAULT_TIMELINE_RESPONSE], indent=4, sort_keys=True),
            ),
            (
                "45.83.66.65",
                "xml",
                textwrap.dedent(
                    """\
                    <?xml version="1.0" ?>
                    <root>
                    \t<item>
                    \t\t<ip>45.83.66.65</ip>
                    \t\t<metadata>
                    \t\t\t<end>2023-01-09T15:52:21.797662573Z</end>
                    \t\t\t<field>classification</field>
                    \t\t\t<granularity>1d</granularity>
                    \t\t\t<ip>45.83.66.65</ip>
                    \t\t\t<metric>count</metric>
                    \t\t\t<start>2023-01-08T00:00:00Z</start>
                    \t\t</metadata>
                    \t\t<results></results>
                    \t</item>
                    </root>"""
                ),
            ),
        ),
    )
    def test_timeline(self, api_client, ip_address, output_format, expected):
        """Quickly check IP address for similar IPs"""
        runner = CliRunner()

        api_client.timeline.return_value = self.DEFAULT_TIMELINE_RESPONSE

        result = runner.invoke(subcommand.timeline, ["-f", output_format, ip_address])
        assert result.exit_code == 0
        assert result.output.strip("\n") == expected
        api_client.timeline.assert_called_with(
            ip_address=ip_address, days=None, field=None
        )

    @pytest.mark.parametrize(
        "ip_address, mock_response, expected",
        (
            (
                "45.83.66.65",
                DEFAULT_TIMELINE_RESPONSE,
                DEFAULT_TIMELINE_RESPONSE,
            ),
        ),
    )
    def test_input_file(self, api_client, ip_address, mock_response, expected):
        """Get IP address information from input file."""
        runner = CliRunner()

        api_client.timeline.return_value = expected

        result = runner.invoke(
            subcommand.timeline, ["-f", "json", "-i", StringIO(ip_address)]
        )
        assert result.exit_code == 0
        assert result.output.strip("\n") == json.dumps(
            [expected], indent=4, sort_keys=True
        )
        api_client.timeline.assert_called_with(
            ip_address=ip_address, days=None, field=None
        )

    @pytest.mark.parametrize(
        "ip_address, mock_response, expected",
        (
            (
                "45.83.66.65",
                DEFAULT_TIMELINE_RESPONSE,
                DEFAULT_TIMELINE_RESPONSE,
            ),
        ),
    )
    def test_stdin_input(self, api_client, ip_address, mock_response, expected):
        """Quickly check IP address from stdin."""
        runner = CliRunner()

        api_client.timeline.return_value = mock_response

        result = runner.invoke(subcommand.timeline, ["-f", "json"], input=ip_address)
        assert result.exit_code == 0
        assert result.output.strip("\n") == json.dumps(
            [expected], indent=4, sort_keys=True
        )
        api_client.timeline.assert_called_with(
            ip_address=ip_address, days=None, field=None
        )

    def test_no_ip_address_passed(self, api_client):
        """Usage is returned if no IP address or input file is passed."""
        runner = CliRunner()

        with patch("greynoise.cli.helper.sys") as sys:
            sys.stdin.isatty.return_value = True
            result = runner.invoke(
                subcommand.timeline, parent=Context(main, info_name="greynoise")
            )
        assert result.exit_code == -1
        assert "Usage: greynoise timeline" in result.output
        api_client.timeline.assert_not_called()

    def test_input_file_invalid_ip_addresses_passed(self, api_client):
        """Error returned if only invalid IP addresses are passed in input file."""
        runner = CliRunner()

        expected = (
            "Error: at least one valid IP address must be passed either as an "
            "argument (IP_ADDRESS) or through the -i/--input_file option."
        )

        result = runner.invoke(
            subcommand.timeline,
            ["-i", StringIO("not-an-ip")],
            parent=Context(main, info_name="greynoise"),
        )
        assert result.exit_code == -1
        assert "Usage: greynoise timeline" in result.output
        assert expected in result.output
        api_client.timeline.assert_not_called()

    def test_invalid_ip_address_as_argument(self, api_client):
        """Quick subcommand fails when ip_address is invalid."""
        runner = CliRunner()

        expected = "Error: Invalid value for '[IP_ADDRESS]...': not-an-ip\n"

        result = runner.invoke(subcommand.timeline, ["not-an-ip"])
        assert result.exit_code == 2
        assert "Usage: timeline [OPTIONS] [IP_ADDRESS]..." in result.output
        assert expected in result.output
        api_client.timeline.assert_not_called()

    def test_request_failure(self, api_client, caplog):
        """Error is displayed on API request failure."""
        runner = CliRunner()

        api_client.timeline.side_effect = RequestFailure(
            401, {"message": "forbidden", "status": "error"}
        )
        expected = "API error: forbidden"

        result = runner.invoke(subcommand.timeline, ["8.8.8.8"])
        assert result.exit_code == -1
        assert caplog.records[0].message == expected

    def test_api_key_not_found(self):
        """Error is displayed if API key is not found."""
        runner = CliRunner()

        with patch("greynoise.cli.decorator.load_config") as load_config:
            load_config.return_value = {"api_key": ""}
            result = runner.invoke(
                subcommand.timeline,
                ["8.8.8.8"],
                parent=Context(main, info_name="greynoise"),
            )
            assert result.exit_code == -1
            assert "Error: API key not found" in result.output


class TestTimelineHourly(object):
    """TimelineHourly subcommand tests."""

    DEFAULT_TIMELINEHOURLY_RESPONSE = {
        "activity": [
            {
                "asn": "AS208843",
                "category": "business",
                "city": "Berlin",
                "classification": "benign",
                "country": "Germany",
                "country_code": "DE",
                "destinations": [{"country": "Serbia", "country_code": "RS"}],
                "hassh_fingerprints": [],
                "http_paths": [],
                "http_user_agents": [],
                "ja3_fingerprints": [],
                "organization": "Alpha Strike Labs GmbH",
                "protocols": [
                    {
                        "port": "5985",
                        "transport_protocol": "TCP",
                    }
                ],
                "rdns": "",
                "region": "Berlin",
                "spoofable": "true",
                "tags": [
                    {
                        "category": "actor",
                        "description": "Tag description",
                        "intention": "benign",
                        "name": "Alpha Strike Labs",
                    }
                ],
                "timestamp": "2023-01-09T05:00:00Z",
                "tor": "false",
                "vpn": "false",
                "vpn_service": "",
            }
        ],
        "ip": "45.83.66.65",
        "metadata": {
            "end_time": "2023-01-09T15:58:06.82558957Z",
            "ip": "45.83.66.65",
            "limit": "100",
            "next_cursor": "b2Zmc2V0PTEwMA==",
            "start_time": "2023-01-08T00:00:00Z",
        },
    }

    @pytest.mark.parametrize(
        "ip_address, output_format, expected",
        (
            (
                "45.83.66.65",
                "json",
                json.dumps([DEFAULT_TIMELINEHOURLY_RESPONSE], indent=4, sort_keys=True),
            ),
            (
                "45.83.66.65",
                "xml",
                textwrap.dedent(
                    """\
                    <?xml version="1.0" ?>
                    <root>
                    \t<item>
                    \t\t<activity>
                    \t\t\t<asn>AS208843</asn>
                    \t\t\t<category>business</category>
                    \t\t\t<city>Berlin</city>
                    \t\t\t<classification>benign</classification>
                    \t\t\t<country>Germany</country>
                    \t\t\t<country_code>DE</country_code>
                    \t\t\t<destinations>
                    \t\t\t\t<country>Serbia</country>
                    \t\t\t\t<country_code>RS</country_code>
                    \t\t\t</destinations>
                    \t\t\t<hassh_fingerprints></hassh_fingerprints>
                    \t\t\t<http_paths></http_paths>
                    \t\t\t<http_user_agents></http_user_agents>
                    \t\t\t<ja3_fingerprints></ja3_fingerprints>
                    \t\t\t<organization>Alpha Strike Labs GmbH</organization>
                    \t\t\t<protocols>
                    \t\t\t\t<port>5985</port>
                    \t\t\t\t<transport_protocol>TCP</transport_protocol>
                    \t\t\t</protocols>
                    \t\t\t<rdns></rdns>
                    \t\t\t<region>Berlin</region>
                    \t\t\t<spoofable>true</spoofable>
                    \t\t\t<tags>
                    \t\t\t\t<category>actor</category>
                    \t\t\t\t<description>Tag description</description>
                    \t\t\t\t<intention>benign</intention>
                    \t\t\t\t<name>Alpha Strike Labs</name>
                    \t\t\t</tags>
                    \t\t\t<timestamp>2023-01-09T05:00:00Z</timestamp>
                    \t\t\t<tor>false</tor>
                    \t\t\t<vpn>false</vpn>
                    \t\t\t<vpn_service></vpn_service>
                    \t\t</activity>
                    \t\t<ip>45.83.66.65</ip>
                    \t\t<metadata>
                    \t\t\t<end_time>2023-01-09T15:58:06.82558957Z</end_time>
                    \t\t\t<ip>45.83.66.65</ip>
                    \t\t\t<limit>100</limit>
                    \t\t\t<next_cursor>b2Zmc2V0PTEwMA==</next_cursor>
                    \t\t\t<start_time>2023-01-08T00:00:00Z</start_time>
                    \t\t</metadata>
                    \t</item>
                    </root>"""
                ),
            ),
        ),
    )
    def test_timelinehourly(self, api_client, ip_address, output_format, expected):
        """Quickly check IP address for similar IPs"""
        runner = CliRunner()

        api_client.timelinehourly.return_value = self.DEFAULT_TIMELINEHOURLY_RESPONSE

        result = runner.invoke(
            subcommand.timelinehourly, ["-f", output_format, ip_address]
        )
        assert result.exit_code == 0
        assert result.output.strip("\n") == expected
        api_client.timelinehourly.assert_called_with(ip_address=ip_address, days=None)

    @pytest.mark.parametrize(
        "ip_address, mock_response, expected",
        (
            (
                "45.83.66.65",
                DEFAULT_TIMELINEHOURLY_RESPONSE,
                DEFAULT_TIMELINEHOURLY_RESPONSE,
            ),
        ),
    )
    def test_input_file(self, api_client, ip_address, mock_response, expected):
        """Get IP address information from input file."""
        runner = CliRunner()

        api_client.timelinehourly.return_value = expected

        result = runner.invoke(
            subcommand.timelinehourly, ["-f", "json", "-i", StringIO(ip_address)]
        )
        assert result.exit_code == 0
        assert result.output.strip("\n") == json.dumps(
            [expected], indent=4, sort_keys=True
        )
        api_client.timelinehourly.assert_called_with(ip_address=ip_address, days=None)

    @pytest.mark.parametrize(
        "ip_address, mock_response, expected",
        (
            (
                "45.83.66.65",
                DEFAULT_TIMELINEHOURLY_RESPONSE,
                DEFAULT_TIMELINEHOURLY_RESPONSE,
            ),
        ),
    )
    def test_stdin_input(self, api_client, ip_address, mock_response, expected):
        """Quickly check IP address from stdin."""
        runner = CliRunner()

        api_client.timelinehourly.return_value = mock_response

        result = runner.invoke(
            subcommand.timelinehourly, ["-f", "json"], input=ip_address
        )
        assert result.exit_code == 0
        assert result.output.strip("\n") == json.dumps(
            [expected], indent=4, sort_keys=True
        )
        api_client.timelinehourly.assert_called_with(ip_address=ip_address, days=None)

    def test_no_ip_address_passed(self, api_client):
        """Usage is returned if no IP address or input file is passed."""
        runner = CliRunner()

        with patch("greynoise.cli.helper.sys") as sys:
            sys.stdin.isatty.return_value = True
            result = runner.invoke(
                subcommand.timelinehourly, parent=Context(main, info_name="greynoise")
            )
        assert result.exit_code == -1
        assert "Usage: greynoise timelinehourly" in result.output
        api_client.timelinehourly.assert_not_called()

    def test_input_file_invalid_ip_addresses_passed(self, api_client):
        """Error returned if only invalid IP addresses are passed in input file."""
        runner = CliRunner()

        expected = (
            "Error: at least one valid IP address must be passed either as an "
            "argument (IP_ADDRESS) or through the -i/--input_file option."
        )

        result = runner.invoke(
            subcommand.timelinehourly,
            ["-i", StringIO("not-an-ip")],
            parent=Context(main, info_name="greynoise"),
        )
        assert result.exit_code == -1
        assert "Usage: greynoise timelinehourly" in result.output
        assert expected in result.output
        api_client.timelinehourly.assert_not_called()

    def test_invalid_ip_address_as_argument(self, api_client):
        """Quick subcommand fails when ip_address is invalid."""
        runner = CliRunner()

        expected = "Error: Invalid value for '[IP_ADDRESS]...': not-an-ip\n"

        result = runner.invoke(subcommand.timelinehourly, ["not-an-ip"])
        assert result.exit_code == 2
        assert "Usage: timelinehourly [OPTIONS] [IP_ADDRESS]..." in result.output
        assert expected in result.output
        api_client.timelinehourly.assert_not_called()

    def test_request_failure(self, api_client, caplog):
        """Error is displayed on API request failure."""
        runner = CliRunner()

        api_client.timelinehourly.side_effect = RequestFailure(
            401, {"message": "forbidden", "status": "error"}
        )
        expected = "API error: forbidden"

        result = runner.invoke(subcommand.timelinehourly, ["8.8.8.8"])
        assert result.exit_code == -1
        assert caplog.records[0].message == expected

    def test_api_key_not_found(self):
        """Error is displayed if API key is not found."""
        runner = CliRunner()

        with patch("greynoise.cli.decorator.load_config") as load_config:
            load_config.return_value = {"api_key": ""}
            result = runner.invoke(
                subcommand.timelinehourly,
                ["8.8.8.8"],
                parent=Context(main, info_name="greynoise"),
            )
            assert result.exit_code == -1
            assert "Error: API key not found" in result.output


class TestTimelineDaily(object):
    """TimelineHourly subcommand tests."""

    DEFAULT_TIMELINEDAILY_RESPONSE = {
        "activity": [
            {
                "asn": "AS208843",
                "category": "business",
                "city": "Berlin",
                "classification": "benign",
                "country": "Germany",
                "country_code": "DE",
                "destinations": [{"country": "Serbia", "country_code": "RS"}],
                "hassh_fingerprints": [],
                "http_paths": [],
                "http_user_agents": [],
                "ja3_fingerprints": [],
                "organization": "Alpha Strike Labs GmbH",
                "protocols": [
                    {
                        "port": "5985",
                        "transport_protocol": "TCP",
                    }
                ],
                "rdns": "",
                "region": "Berlin",
                "spoofable": "true",
                "tags": [
                    {
                        "category": "actor",
                        "description": "Tag description",
                        "intention": "benign",
                        "name": "Alpha Strike Labs",
                    }
                ],
                "timestamp": "2023-01-09T05:00:00Z",
                "tor": "false",
                "vpn": "false",
                "vpn_service": "",
            }
        ],
        "ip": "45.83.66.65",
        "metadata": {
            "end_time": "2023-01-09T15:58:06.82558957Z",
            "ip": "45.83.66.65",
            "limit": "100",
            "next_cursor": "b2Zmc2V0PTEwMA==",
            "start_time": "2023-01-08T00:00:00Z",
        },
    }

    @pytest.mark.parametrize(
        "ip_address, output_format, expected",
        (
            (
                "45.83.66.65",
                "json",
                json.dumps([DEFAULT_TIMELINEDAILY_RESPONSE], indent=4, sort_keys=True),
            ),
            (
                "45.83.66.65",
                "xml",
                textwrap.dedent(
                    """\
                    <?xml version="1.0" ?>
                    <root>
                    \t<item>
                    \t\t<activity>
                    \t\t\t<asn>AS208843</asn>
                    \t\t\t<category>business</category>
                    \t\t\t<city>Berlin</city>
                    \t\t\t<classification>benign</classification>
                    \t\t\t<country>Germany</country>
                    \t\t\t<country_code>DE</country_code>
                    \t\t\t<destinations>
                    \t\t\t\t<country>Serbia</country>
                    \t\t\t\t<country_code>RS</country_code>
                    \t\t\t</destinations>
                    \t\t\t<hassh_fingerprints></hassh_fingerprints>
                    \t\t\t<http_paths></http_paths>
                    \t\t\t<http_user_agents></http_user_agents>
                    \t\t\t<ja3_fingerprints></ja3_fingerprints>
                    \t\t\t<organization>Alpha Strike Labs GmbH</organization>
                    \t\t\t<protocols>
                    \t\t\t\t<port>5985</port>
                    \t\t\t\t<transport_protocol>TCP</transport_protocol>
                    \t\t\t</protocols>
                    \t\t\t<rdns></rdns>
                    \t\t\t<region>Berlin</region>
                    \t\t\t<spoofable>true</spoofable>
                    \t\t\t<tags>
                    \t\t\t\t<category>actor</category>
                    \t\t\t\t<description>Tag description</description>
                    \t\t\t\t<intention>benign</intention>
                    \t\t\t\t<name>Alpha Strike Labs</name>
                    \t\t\t</tags>
                    \t\t\t<timestamp>2023-01-09T05:00:00Z</timestamp>
                    \t\t\t<tor>false</tor>
                    \t\t\t<vpn>false</vpn>
                    \t\t\t<vpn_service></vpn_service>
                    \t\t</activity>
                    \t\t<ip>45.83.66.65</ip>
                    \t\t<metadata>
                    \t\t\t<end_time>2023-01-09T15:58:06.82558957Z</end_time>
                    \t\t\t<ip>45.83.66.65</ip>
                    \t\t\t<limit>100</limit>
                    \t\t\t<next_cursor>b2Zmc2V0PTEwMA==</next_cursor>
                    \t\t\t<start_time>2023-01-08T00:00:00Z</start_time>
                    \t\t</metadata>
                    \t</item>
                    </root>"""
                ),
            ),
        ),
    )
    def test_timelinedaily(self, api_client, ip_address, output_format, expected):
        """Quickly check IP address for similar IPs"""
        runner = CliRunner()

        api_client.timelinedaily.return_value = self.DEFAULT_TIMELINEDAILY_RESPONSE

        result = runner.invoke(
            subcommand.timelinedaily, ["-f", output_format, ip_address]
        )
        assert result.exit_code == 0
        assert result.output.strip("\n") == expected
        api_client.timelinedaily.assert_called_with(ip_address=ip_address, days=None)

    @pytest.mark.parametrize(
        "ip_address, mock_response, expected",
        (
            (
                "45.83.66.65",
                DEFAULT_TIMELINEDAILY_RESPONSE,
                DEFAULT_TIMELINEDAILY_RESPONSE,
            ),
        ),
    )
    def test_input_file(self, api_client, ip_address, mock_response, expected):
        """Get IP address information from input file."""
        runner = CliRunner()

        api_client.timelinedaily.return_value = expected

        result = runner.invoke(
            subcommand.timelinedaily, ["-f", "json", "-i", StringIO(ip_address)]
        )
        assert result.exit_code == 0
        assert result.output.strip("\n") == json.dumps(
            [expected], indent=4, sort_keys=True
        )
        api_client.timelinedaily.assert_called_with(ip_address=ip_address, days=None)

    @pytest.mark.parametrize(
        "ip_address, mock_response, expected",
        (
            (
                "45.83.66.65",
                DEFAULT_TIMELINEDAILY_RESPONSE,
                DEFAULT_TIMELINEDAILY_RESPONSE,
            ),
        ),
    )
    def test_stdin_input(self, api_client, ip_address, mock_response, expected):
        """Quickly check IP address from stdin."""
        runner = CliRunner()

        api_client.timelinedaily.return_value = mock_response

        result = runner.invoke(
            subcommand.timelinedaily, ["-f", "json"], input=ip_address
        )
        assert result.exit_code == 0
        assert result.output.strip("\n") == json.dumps(
            [expected], indent=4, sort_keys=True
        )
        api_client.timelinedaily.assert_called_with(ip_address=ip_address, days=None)

    def test_no_ip_address_passed(self, api_client):
        """Usage is returned if no IP address or input file is passed."""
        runner = CliRunner()

        with patch("greynoise.cli.helper.sys") as sys:
            sys.stdin.isatty.return_value = True
            result = runner.invoke(
                subcommand.timelinedaily, parent=Context(main, info_name="greynoise")
            )
        assert result.exit_code == -1
        assert "Usage: greynoise timelinedaily" in result.output
        api_client.timelinedaily.assert_not_called()

    def test_input_file_invalid_ip_addresses_passed(self, api_client):
        """Error returned if only invalid IP addresses are passed in input file."""
        runner = CliRunner()

        expected = (
            "Error: at least one valid IP address must be passed either as an "
            "argument (IP_ADDRESS) or through the -i/--input_file option."
        )

        result = runner.invoke(
            subcommand.timelinedaily,
            ["-i", StringIO("not-an-ip")],
            parent=Context(main, info_name="greynoise"),
        )
        assert result.exit_code == -1
        assert "Usage: greynoise timelinedaily" in result.output
        assert expected in result.output
        api_client.timelinehourly.assert_not_called()

    def test_invalid_ip_address_as_argument(self, api_client):
        """Quick subcommand fails when ip_address is invalid."""
        runner = CliRunner()

        expected = "Error: Invalid value for '[IP_ADDRESS]...': not-an-ip\n"

        result = runner.invoke(subcommand.timelinedaily, ["not-an-ip"])
        assert result.exit_code == 2
        assert "Usage: timelinedaily [OPTIONS] [IP_ADDRESS]..." in result.output
        assert expected in result.output
        api_client.timelinedaily.assert_not_called()

    def test_request_failure(self, api_client, caplog):
        """Error is displayed on API request failure."""
        runner = CliRunner()

        api_client.timelinedaily.side_effect = RequestFailure(
            401, {"message": "forbidden", "status": "error"}
        )
        expected = "API error: forbidden"

        result = runner.invoke(subcommand.timelinedaily, ["8.8.8.8"])
        assert result.exit_code == -1
        assert caplog.records[0].message == expected

    def test_api_key_not_found(self):
        """Error is displayed if API key is not found."""
        runner = CliRunner()

        with patch("greynoise.cli.decorator.load_config") as load_config:
            load_config.return_value = {"api_key": ""}
            result = runner.invoke(
                subcommand.timelinedaily,
                ["8.8.8.8"],
                parent=Context(main, info_name="greynoise"),
            )
            assert result.exit_code == -1
            assert "Error: API key not found" in result.output
