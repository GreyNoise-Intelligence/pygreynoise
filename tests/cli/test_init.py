"""CLI main command test cases."""

import pytest
from click.testing import CliRunner

from greynoise.cli import main

# from mock import Mock, patch


class TestMain(object):
    """Main command tests."""

    @pytest.mark.parametrize("help_option", ("-h", "--help"))
    def test_help(self, help_option):
        """Usage string is printed."""
        runner = CliRunner()
        result = runner.invoke(main, help_option)

        assert result.exit_code == 0
        assert "Usage:" in result.output
