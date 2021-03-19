"""GreyNoise command line Interface."""

import click
import structlog
from click_default_group import DefaultGroup
from click_repl import register_repl

from greynoise.cli import subcommand
from greynoise.util import configure_logging


@click.group(
    cls=DefaultGroup,
    default_if_no_args=False,
    context_settings={"help_option_names": ("-h", "--help")},
)
def main():
    """GreyNoise CLI."""
    if not structlog.is_configured():
        configure_logging()


SUBCOMMAND_FUNCTIONS = [
    subcommand_function
    for subcommand_function in vars(subcommand).values()
    if isinstance(subcommand_function, click.Command)
]

for subcommand_function in SUBCOMMAND_FUNCTIONS:
    main.add_command(subcommand_function)

register_repl(main)
