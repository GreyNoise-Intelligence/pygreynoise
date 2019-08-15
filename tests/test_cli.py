"""GreyNoise CLI test cases."""

import argparse
import datetime
import textwrap

import pytest

from mock import Mock, patch

from greynoise.cli import (
    actors, context, multi_quick_check, main, noise, parse_arguments, quick_check,
    setup,
)


class TestMain(object):
    """Main entry point tests."""

    def test_argv(self, capsys):
        """sys.argv used if argv not explicitly passed."""
        with patch('greynoise.cli.sys') as sys:
            sys.argv = ['greynoise', '-h']

            with pytest.raises(SystemExit):
                main()

            captured = capsys.readouterr()
            assert captured.out.startswith('usage:')

    @pytest.mark.parametrize(
        'format_option, result, expected',
        (
            (
                "json",
                {"a": "result"},
                '{"a": "result"}\n',
            ),
            (
                "xml",
                {"a": "result"},
                textwrap.dedent(
                    """\
                    <?xml version="1.0" ?>
                    <root>
                    \t<a type="str">result</a>
                    </root>

                    """
                )
            ),
        ),
    )
    def test_output_format(self, capsys, format_option, result, expected):
        """Output is formatted."""
        with patch('greynoise.cli.parse_arguments') as parse_arguments:
            func = Mock(return_value=result)
            args = argparse.Namespace(format=format_option, func=func)
            parse_arguments.return_value = args

            main()
            captured = capsys.readouterr()
            assert captured.out == expected


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
        args = parse_arguments(
            ["multi_quick_check", "0.0.0.0", "0.0.0.1"])
        assert args.func == multi_quick_check

    def test_multi_quick_check_failure(self):
        """Multi quick check subcommand fails is ip validatin fails."""
        with pytest.raises(SystemExit):
            parse_arguments([
                "multi_quick_check",
                "<invalid_ip_address#1>",
                "<invalid_ip_address#2>",
            ])

    def test_actors(self):
        """Actors subcommand called."""
        args = parse_arguments(["actors"])
        assert args.func == actors


class TestSubcommands(object):
    """CLI subcommands test cases."""

    def test_setup(self):
        """Setup subcommand."""
        with patch("greynoise.cli.save_config") as save_config:
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
