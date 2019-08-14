"""GreyNoise command line Interface."""

import os
import sys

from argparse import ArgumentParser

from greynoise.gncli import run_query
from greynoise.util import (
    CONFIG_FILE,
    load_config,
    save_config,
)


def main(argv=None):
    """Entry point for the greynoise CLI."""
    if argv is None:
        argv = sys.argv[1:]

    args = parse_arguments(argv)
    args.func(args)
    return


def setup(args):
    """Configure API key."""
    config = {'api_key': args.api_key}
    save_config(config)
    print('Configuration saved to {!r}'.format(CONFIG_FILE))


def run(args):
    """Run GNQL query."""
    api_key = args.api_key
    if not api_key:
        config = load_config()
        api_key = config['api_key']
    if not api_key:
        prog = os.path.basename(sys.argv[0])
        print(
            "Error: API key not found.\n\n"
            "To fix this problem, please use any of the following methods:\n"
            "- Run {!r} to save it to the configuration file.\n"
            "- Pass it to {!r} using the -k/--api-key option.\n"
            "- Set it in the GREYNOISE_API_KEY environment variable.\n"
            .format(
                "{} setup".format(prog),
                "{} run".format(prog),
            )
        )

    run_query(
        args.output_file,
        args.output_format,
        args.query_type,
        args.query,
        args.verbose,
    )


def parse_arguments(argv):
    """Parse command line arguments."""
    parser = ArgumentParser(description=__doc__)
    parser.set_defaults(func=lambda args: parser.print_help())

    subparsers = parser.add_subparsers(help="Subcommands")

    setup_parser = subparsers.add_parser("setup", help=setup.__doc__.rstrip("."))
    setup_parser.add_argument(
        "-k",
        "--api-key",
        required=True,
        help="Key to include in API requests",
    )
    setup_parser.set_defaults(func=setup)

    run_parser = subparsers.add_parser("run", help=run.__doc__.rstrip("."))
    run_parser.add_argument("query", help="Query to be executed")
    run_parser.add_argument(
        "-k",
        "--api-key",
        help="Key to include in API requests",
    )
    run_parser.add_argument(
        "-f",
        "--file",
        dest="output_filename",
        help="Output file name",
    )
    run_parser.add_argument(
        "-o",
        "--output",
        dest="output_format",
        help="Output format",
    )
    run_parser.add_argument(
        "-t",
        "--type",
        dest="query_type",
        help="Query type",
    )
    run_parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Verbose output",
    )
    run_parser.set_defaults(func=run)

    args = parser.parse_args()
    return args
