"""GreyNoise CLI test cases."""

import argparse
import textwrap

import pytest

from mock import Mock, patch

from greynoise.cli import main


class TestMain(object):
    """Main entry point tests."""

    def test_argv(self, capsys):
        """sys.argv used if argv not explicitly passed."""
        with patch("greynoise.cli.sys") as sys:
            sys.argv = ["greynoise", "-h"]

            with pytest.raises(SystemExit):
                main()

            captured = capsys.readouterr()
            assert captured.out.startswith("usage:")

    @pytest.mark.parametrize(
        "format_option, result, expected",
        (
            ("json", {"a": "result"}, '{"a": "result"}\n'),
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
                ),
            ),
        ),
    )
    def test_output_format(self, capsys, format_option, result, expected):
        """Output is formatted."""
        with patch("greynoise.cli.parse_arguments") as parse_arguments:
            func = Mock(return_value=result)
            args = argparse.Namespace(format=format_option, func=func)
            parse_arguments.return_value = args

            main()
            captured = capsys.readouterr()
            assert captured.out == expected
