"""CLI subcommands test cases."""

import argparse

from mock import Mock, patch

from greynoise.cli.subcommand import (
    actors,
    context,
    multi_quick_check,
    noise,
    quick_check,
    setup,
)


class TestSubcommands(object):
    """CLI subcommands test cases."""

    def test_setup(self):
        """Setup subcommand."""
        with patch("greynoise.cli.subcommand.save_config") as save_config:
            api_key = "<api_key>"
            expected = {"api_key": api_key}
            args = argparse.Namespace(api_key=api_key)
            setup(args)
            save_config.assert_called_with(expected)

    def test_noise(self):
        """Noise subcommand."""
        api_client = Mock()
        date = "<date>"
        args = argparse.Namespace(date=date, api_client=api_client)

        noise(args)
        api_client.get_noise.assert_called_with(date=date)

    def test_context(self):
        """Context subcommand."""
        api_client = Mock()
        ip_address = "<ip_address>"
        args = argparse.Namespace(ip_address=ip_address, api_client=api_client)

        context(args)
        api_client.get_context.assert_called_with(ip_address=ip_address)

    def test_quick_check(self):
        """Quick check subcommand."""
        api_client = Mock()
        ip_address = "<ip_address>"
        args = argparse.Namespace(ip_address=ip_address, api_client=api_client)

        quick_check(args)
        api_client.get_noise_status.assert_called_with(ip_address=ip_address)

    def test_multi_quick_check(self):
        """Multi quick check subcommand."""
        api_client = Mock()
        ip_addresses = ["<ip_address#1>", "<ip_address#2>"]
        args = argparse.Namespace(ip_address=ip_addresses, api_client=api_client)

        multi_quick_check(args)
        api_client.get_noise_status_bulk.assert_called_with(ip_addresses=ip_addresses)

    def test_actors(self):
        """Actors subcommand."""
        api_client = Mock()
        args = argparse.Namespace(api_client=api_client)

        actors(args)
        api_client.get_actors.assert_called_with()
