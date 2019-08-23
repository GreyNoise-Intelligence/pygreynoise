"""CLI main command test cases."""
from click.testing import CliRunner
from mock import patch

from greynoise.cli import main


class TestMain(object):
    """Main command tests."""

    def test_no_arguments_passed(self):
        """Main succeeds even if no arguments are passed."""
        runner = CliRunner()
        with patch("greynoise.cli.load_config") as load_config:
            load_config.return_value = {"api_key": "<api_key>"}
            result = runner.invoke(main, [])

        assert result.exit_code == 0

    def test_api_key_not_found(self):
        """Main command fails if API key is not found."""
        runner = CliRunner()
        with patch("greynoise.cli.load_config") as load_config:
            load_config.return_value = {"api_key": ""}
            result = runner.invoke(main, [])

        assert result.exit_code == -1
        assert "Error: API key not found" in result.output
