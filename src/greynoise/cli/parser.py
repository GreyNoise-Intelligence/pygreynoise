"""CLI parser."""

import os
import sys

from argparse import ArgumentParser

from greynoise.api import GreyNoise
from greynoise.cli.parameter import date_parameter, ip_address_parameter
from greynoise.cli.subcommand import (
    actors,
    context,
    multi_quick_check,
    noise,
    quick_check,
    setup,
)
from greynoise.util import load_config


def parse_arguments(argv):
    """Parse command line arguments."""
    parser = ArgumentParser(description=__doc__)
    parser.set_defaults(func=lambda args: parser.print_help())
    parser.add_argument("-k", "--api-key", help="Key to include in API requests")
    parser.add_argument(
        "-f",
        "--format",
        choices=["json", "xml"],
        default="json",
        help="Output format (%(default)s by default",
    )

    subparsers = parser.add_subparsers(help="Subcommands")

    setup_parser = subparsers.add_parser("setup", help=setup.__doc__.rstrip("."))
    setup_parser.add_argument(
        "-k", "--api-key", required=True, help="Key to include in API requests"
    )
    setup_parser.set_defaults(func=setup)

    noise_parser = subparsers.add_parser("noise", help=noise.__doc__.rstrip("."))
    noise_parser.add_argument(
        "-d",
        "--date",
        type=date_parameter,
        help="Date to use as filter (format: YYYY-MM-DD)",
    )
    noise_parser.set_defaults(func=noise)

    context_parser = subparsers.add_parser("context", help=context.__doc__.rstrip("."))
    context_parser.add_argument(
        "ip_address", type=ip_address_parameter, help="IP address"
    )
    context_parser.set_defaults(func=context)

    quick_check_parser = subparsers.add_parser(
        "quick_check", help=quick_check.__doc__.rstrip(".")
    )
    quick_check_parser.add_argument(
        "ip_address", type=ip_address_parameter, help="IP address"
    )
    quick_check_parser.set_defaults(func=quick_check)

    multi_quick_check_parser = subparsers.add_parser(
        "multi_quick_check", help=multi_quick_check.__doc__.rstrip(".")
    )
    multi_quick_check_parser.add_argument(
        "ip_address", type=ip_address_parameter, nargs="+", help="IP address"
    )
    multi_quick_check_parser.set_defaults(func=multi_quick_check)

    actors_parser = subparsers.add_parser("actors", help=actors.__doc__.rstrip("."))
    actors_parser.set_defaults(func=actors)

    args = parser.parse_args(argv)
    if not args.api_key:
        config = load_config()
        if not config["api_key"]:
            prog = os.path.basename(sys.argv[0])
            print(
                "Error: API key not found.\n\n"
                "To fix this problem, please use any of the following methods "
                "(in order of precedence):\n"
                "- Pass it using the -k/--api-key option.\n"
                "- Set it in the GREYNOISE_API_KEY environment variable.\n"
                "- Run {!r} to save it to the configuration file.\n".format(
                    "{} setup".format(prog)
                )
            )
            sys.exit(-1)
        args.api_key = config["api_key"]
        args.api_client = GreyNoise(args.api_key)

    return args
