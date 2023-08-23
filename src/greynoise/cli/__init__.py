"""GreyNoise command line Interface."""

import click
import typer
import platform

from click_default_group import DefaultGroup
from click_repl import register_repl

from greynoise.cli import subcommand


@click.group(
    cls=DefaultGroup,
    default_if_no_args=False,
    context_settings={"help_option_names": ("-h", "--help")},
)
def main():
    """GreyNoise CLI."""


SUBCOMMAND_FUNCTIONS = [
    subcommand_function
    for subcommand_function in vars(subcommand).values()
    if isinstance(subcommand_function, click.Command)
]

for subcommand_function in SUBCOMMAND_FUNCTIONS:
    main.add_command(subcommand_function)

if platform.python_version() >= "3.7.2":
    from greynoiselabs.cli import app
    typer_click_object = typer.main.get_command(app)
    main.add_command(typer_click_object, "labs")

register_repl(main)
