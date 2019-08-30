"""GreyNoise command line Interface."""

import os
import sys

import click

from click_default_group import DefaultGroup
from greynoise.api import GreyNoise
from greynoise.cli import subcommand
from greynoise.util import load_config


@click.group(
    cls=DefaultGroup,
    default="query",
    default_if_no_args=True,
    context_settings={"help_option_names": ("-h", "--help")},
)
@click.option("-k", "--api-key", help="Key to include in API requests")
@click.option(
    "-f",
    "--format",
    "output_format",
    type=click.Choice(["json", "txt", "xml"]),
    default="txt",
    help="Output format",
)
@click.option("-i", "--input", "input_file", type=click.File(), help="Input file")
@click.option("-v", "--verbose", is_flag=True, help="Verbose output")
@click.pass_context
def main(context, api_key, output_format, input_file, verbose):
    """GreyNoise CLI."""
    if api_key is None and context.invoked_subcommand != "setup":
        config = load_config()
        if not config["api_key"]:
            prog = os.path.basename(sys.argv[0])
            click.echo(
                "\nError: API key not found.\n\n"
                "To fix this problem, please use any of the following methods "
                "(in order of precedence):\n"
                "- Pass it using the -k/--api-key option.\n"
                "- Set it in the GREYNOISE_API_KEY environment variable.\n"
                "- Run {!r} to save it to the configuration file.\n".format(
                    "{} setup".format(prog)
                )
            )
            context.exit(-1)
        api_key = config["api_key"]

    context.obj = {
        "api_client": GreyNoise(api_key),
        "input_file": input_file,
        "output_format": output_format,
        "verbose": verbose,
    }


SUBCOMMAND_NAMES = [
    "account",
    "alerts",
    "analyze",
    "feedback",
    "filter",
    "help",
    "interesting",
    "ip",
    "pcap",
    "query",
    "quick",
    "setup",
    "signature",
    "stats",
    "version",
]
for subcommand_name in SUBCOMMAND_NAMES:
    main.add_command(getattr(subcommand, subcommand_name))
