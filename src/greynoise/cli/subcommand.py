"""CLI subcommands."""

import sys

import click

from greynoise.cli.decorator import (
    echo_result,
    gnql,
    handle_exceptions,
    pass_api_client,
)
from greynoise.cli.helper import get_queries
from greynoise.cli.parameter import ip_addresses_parameter
from greynoise.util import CONFIG_FILE, save_config, validate_ip


class SubcommandNotImplemented(click.ClickException):
    """Exception used temporarily for subcommands that have not been implemented.

    :param subcommand_name: Name of the subcommand to display in the error message.
    :type subcommand_function: str

    """

    def __init__(self, subcommand_name):
        message = "{!r} subcommand is not implemented yet.".format(subcommand_name)
        super(SubcommandNotImplemented, self).__init__(message)


@click.command()
def account():
    """View information about your GreyNoise account."""
    raise SubcommandNotImplemented("account")


@click.command()
def alerts():
    """List, create, delete, and manage your GreyNoise alerts."""
    raise SubcommandNotImplemented("alerts")


@click.command()
def analyze():
    """Analyze the IP addresses in a log file, stdin, etc."""
    raise SubcommandNotImplemented("analyze")


@click.command()
def feedback():
    """Send feedback directly to the GreyNoise team."""
    raise SubcommandNotImplemented("feedback")


@click.command(name="filter")
def filter_():
    """"Filter the noise from a log file, stdin, etc."""
    raise SubcommandNotImplemented("filter")


@click.command(name="help")
@click.pass_context
def help_(context):
    """Show this message and exit."""
    click.echo(context.parent.get_help())


@click.command()
def interesting():
    """Report an IP as "interesting"."""
    raise SubcommandNotImplemented("interesting")


@click.command()
@click.argument("ip_address", callback=ip_addresses_parameter, nargs=-1)
@click.option("-k", "--api-key", help="Key to include in API requests")
@click.option("-i", "--input", "input_file", type=click.File(), help="Input file")
@click.option(
    "-f",
    "--format",
    "output_format",
    type=click.Choice(["json", "txt", "xml"]),
    default="txt",
    help="Output format",
)
@click.option("-v", "--verbose", is_flag=True, help="Verbose output")
@pass_api_client
@click.pass_context
@echo_result
@handle_exceptions
def ip(context, api_client, api_key, input_file, output_format, verbose, ip_address):
    """Query GreyNoise for all information on a given IP."""
    if input_file is None and not sys.stdin.isatty():
        input_file = click.open_file("-")

    if input_file is None and not ip_address:
        click.echo(context.get_help())
        context.exit(-1)

    ip_addresses = []
    if input_file is not None:
        lines = [line.strip() for line in input_file]
        ip_addresses.extend([line for line in lines if validate_ip(line, strict=False)])
    ip_addresses.extend(list(ip_address))

    if not ip_addresses:
        output = [
            context.command.get_usage(context),
            (
                "Error: at least one valid IP address must be passed either as an "
                "argument (IP_ADDRESS) or through the -i/--input_file option."
            ),
        ]
        click.echo("\n\n".join(output))
        context.exit(-1)

    results = [api_client.ip(ip_address=ip_address) for ip_address in ip_addresses]
    return results


@click.command()
def pcap():
    """Get PCAP for a given IP address."""
    raise SubcommandNotImplemented("pcap")


@gnql
def query(context, api_client, api_key, input_file, output_format, verbose, query):
    """Run a GNQL (GreyNoise Query Language) query."""
    queries = get_queries(context, input_file, query)
    results = [api_client.query(query=query) for query in queries]
    return results


@click.command()
@click.argument("ip_address", callback=ip_addresses_parameter, nargs=-1)
@click.option("-k", "--api-key", help="Key to include in API requests")
@click.option("-i", "--input", "input_file", type=click.File(), help="Input file")
@click.option(
    "-f",
    "--format",
    "output_format",
    type=click.Choice(["json", "txt", "xml"]),
    default="txt",
    help="Output format",
)
@pass_api_client
@click.pass_context
@echo_result
@handle_exceptions
def quick(context, api_client, api_key, input_file, output_format, ip_address):
    """Quickly check whether or not one or many IPs are "noise"."""
    if input_file is None and not sys.stdin.isatty():
        input_file = sys.stdin

    if input_file is None and not ip_address:
        click.echo(context.get_help())
        context.exit(-1)

    ip_addresses = []
    if input_file is not None:
        lines = [line.strip() for line in input_file]
        ip_addresses.extend([line for line in lines if validate_ip(line, strict=False)])
    ip_addresses.extend(list(ip_address))

    if not ip_addresses:
        output = [
            context.command.get_usage(context),
            (
                "Error: at least one valid IP address must be passed either as an "
                "argument (IP_ADDRESS) or through the -i/--input_file option."
            ),
        ]
        click.echo("\n\n".join(output))
        context.exit(-1)

    results = []
    if ip_addresses:
        results.extend(api_client.quick(ip_addresses=ip_addresses))
    return results


@click.command()
@click.option("-k", "--api-key", required=True, help="Key to include in API requests")
def setup(api_key):
    """Configure API key."""
    config = {"api_key": api_key}
    save_config(config)
    click.echo("Configuration saved to {!r}".format(CONFIG_FILE))


@click.command()
def signature():
    """Submit an IDS signature to GreyNoise to be deployed to all GreyNoise nodes."""
    raise SubcommandNotImplemented("signature")


@gnql
def stats(context, api_client, api_key, input_file, output_format, verbose, query):
    """Get aggregate stats from a given GNQL query."""
    queries = get_queries(context, input_file, query)
    results = [api_client.stats(query=query) for query in queries]
    return results


@click.command()
def version():
    """Get version and OS information for your GreyNoise commandline installation."""
    raise SubcommandNotImplemented("version")
