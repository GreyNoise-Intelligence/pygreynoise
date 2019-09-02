"""CLI main command test cases."""

import pytest
from click.testing import CliRunner

from greynoise.cli import main


class TestMain(object):
    """Main command tests."""

    @pytest.mark.parametrize("help_option", ("-h", "--help"))
    def test_help(self, help_option):
        """Main succeeds even if no arguments are passed."""
        runner = CliRunner()
        result = runner.invoke(main, help_option)

        assert result.exit_code == 0
        assert "Usage:" in result.output
