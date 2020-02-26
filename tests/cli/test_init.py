"""CLI main command test cases."""

import pytest
from click.testing import CliRunner
from greynoise.cli import main
from mock import Mock, patch


class TestMain(object):
    """Main command tests."""

    @pytest.mark.parametrize("help_option", ("-h", "--help"))
    def test_help(self, help_option):
        """Usage string is printed."""
        runner = CliRunner()
        result = runner.invoke(main, help_option)

        assert result.exit_code == 0
        assert "Usage:" in result.output

    def test_logging_configured(self):
        """Logging is configured."""
        runner = CliRunner()

        with patch("greynoise.cli.structlog") as structlog, patch(
            "greynoise.cli.configure_logging"
        ) as configure_logging:
            structlog.is_configured.return_value = False
            query_command = Mock()
            with patch.dict(main.commands, query=query_command):
                runner.invoke(main, ["<parameter>"])

        configure_logging.assert_called_once_with()
