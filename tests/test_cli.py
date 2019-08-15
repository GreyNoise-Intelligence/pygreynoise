"""GreyNoise CLI test cases."""

import pytest

from mock import patch

from greynoise.cli import (
    actors, context, multi_quick_check, noise, parse_arguments, quick_check, setup,
)


class TestParseArguments(object):
    """Parse arguments tests."""

    @pytest.fixture(autouse=True)
    def patch_load_config(self):
        """Patch load_config function."""
        with patch("greynoise.cli.load_config"):
            yield

    @pytest.mark.parametrize("api_key_option", ("-k", "--api-key"))
    def test_setup(self, api_key_option):
        """Setup subcommand called."""
        args = parse_arguments(["setup", api_key_option, "<api_key>"])
        assert args.func == setup

    def test_noise(self):
        """Noise subcommand called."""
        args = parse_arguments(["noise"])
        assert args.func == noise

    def test_context(self):
        """Context subcommand called."""
        args = parse_arguments(["context", "<ip_address>"])
        assert args.func == context

    def test_quick_check(self):
        """Quick check subcommand called."""
        args = parse_arguments(["quick_check", "<ip_address>"])
        assert args.func == quick_check

    def test_multi_quick_check(self):
        """Multi quick check subcommand called."""
        args = parse_arguments(
            ["multi_quick_check", "<ip_address#1>", "<ip_address#2>"])
        assert args.func == multi_quick_check

    def test_actors(self):
        """Actors subcommand called."""
        args = parse_arguments(["actors"])
        assert args.func == actors
