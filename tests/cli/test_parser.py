"""CLI parser test cases."""

import datetime

import pytest
from mock import patch

from greynoise.cli.parser import parse_arguments
from greynoise.cli.subcommand import (
    actors,
    context,
    multi_quick_check,
    noise,
    quick_check,
    setup,
)


class TestParseArguments(object):
    """Parse arguments tests."""

    @pytest.fixture(autouse=True)
    def load_config(self):
        """Patch load_config function."""
        with patch("greynoise.cli.parser.load_config") as load_config:
            yield load_config

    @pytest.mark.parametrize("api_key_option", ("-k", "--api-key"))
    def test_setup(self, api_key_option):
        """Setup subcommand called."""
        args = parse_arguments(["setup", api_key_option, "<api_key>"])
        assert args.func == setup

    def test_setup_failure(self):
        """Setup subcommand fails if api_key not passed."""
        with pytest.raises(SystemExit):
            parse_arguments(["setup"])

    def test_noise(self):
        """Noise subcommand called."""
        args = parse_arguments(["noise"])
        assert args.func == noise

    @pytest.mark.parametrize("date_option", ("-d", "--date"))
    def test_noise_with_date(self, date_option):
        """Noise with date subcommand called."""
        args = parse_arguments(["noise", date_option, "2019-01-01"])
        assert args.func == noise
        assert args.date == datetime.date(2019, 1, 1)

    @pytest.mark.parametrize("date_option", ("-d", "--date"))
    def test_noise_with_date_failure(self, date_option):
        """Noise with date subcommand fails if date validation fails."""
        with pytest.raises(SystemExit):
            parse_arguments(["noise", date_option, "not-a-date"])

    def test_context(self):
        """Context subcommand called."""
        args = parse_arguments(["context", "0.0.0.0"])
        assert args.func == context

    def test_context_failure(self):
        """Context subcommand fails if ip address validation fails."""
        with pytest.raises(SystemExit):
            parse_arguments(["context", "<invalid_ip_address>"])

    def test_quick_check(self):
        """Quick check subcommand called."""
        args = parse_arguments(["quick_check", "0.0.0.0"])
        assert args.func == quick_check

    def test_quick_check_failure(self):
        """Quick check subcommand fails if ip address validation fails."""
        with pytest.raises(SystemExit):
            parse_arguments(["quick_check", "<invalid_ip_address>"])

    def test_multi_quick_check(self):
        """Multi quick check subcommand called."""
        args = parse_arguments(["multi_quick_check", "0.0.0.0", "0.0.0.1"])
        assert args.func == multi_quick_check

    def test_multi_quick_check_failure(self):
        """Multi quick check subcommand fails is ip validatin fails."""
        with pytest.raises(SystemExit):
            parse_arguments(
                [
                    "multi_quick_check",
                    "<invalid_ip_address#1>",
                    "<invalid_ip_address#2>",
                ]
            )

    def test_actors(self):
        """Actors subcommand called."""
        args = parse_arguments(["actors"])
        assert args.func == actors

    def test_api_key_not_found(self, capsys, load_config):
        """Error is returned if API is not found."""
        load_config.return_value = {"api_key": ""}

        with pytest.raises(SystemExit):
            parse_arguments(["actors"])

        captured = capsys.readouterr()
        assert captured.out.startswith("Error: API key not found")
