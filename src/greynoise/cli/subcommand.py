"""CLI subcommands."""

import platform
import sys

import click

from greynoise.__version__ import __version__
from greynoise.cli.decorator import (
    gnql_command,
    handle_exceptions,
    ip_lookup_command,
    not_implemented_command,
    pass_api_client,
)
from greynoise.cli.formatter import ANSI_MARKUP
from greynoise.cli.helper import get_ip_addresses, get_queries
from greynoise.cli.parameter import ip_addresses_parameter
from greynoise.util import CONFIG_FILE, DEFAULT_CONFIG, save_config


@not_implemented_command
def account():
    """View information about your GreyNoise account."""


@not_implemented_command
def alerts():
    """List, create, delete, and manage your GreyNoise alerts."""


@not_implemented_command
def analyze():
    """Analyze the IP addresses in a log file, stdin, etc."""


@not_implemented_command
def feedback():
    """Send feedback directly to the GreyNoise team."""


@click.command()
@click.option("-k", "--api-key", help="Key to include in API requests")
@click.option("-i", "--input", "input_file", type=click.File(), help="Input file")
@click.option(
    "-o", "--output", "output_file", type=click.File(mode="w"), help="Output file"
)
@click.option(
    "--noise-only", is_flag=True, help="Select lines containing noisy addresses"
)
@pass_api_client
def filter(api_client, api_key, input_file, output_file, noise_only):
    """"Filter the noise from a log file, stdin, etc."""
    if input_file is None:
        if sys.stdin.isatty():
            input_file = ""
        else:
            input_file = click.open_file("-")
    if output_file is None:
        output_file = click.open_file("-", mode="w")

    output_file.write(ANSI_MARKUP(api_client.filter(input_file, noise_only=noise_only)))


@click.command(name="help")
@click.pass_context
def help_(context):
    """Show this message and exit."""
    click.echo(context.parent.get_help())


@click.command()
@click.argument("ip_address", callback=ip_addresses_parameter, nargs=-1)
@click.option("-k", "--api-key", help="Key to include in API requests")
@click.option("-i", "--input", "input_file", type=click.File(), help="Input file")
@pass_api_client
@click.pass_context
@handle_exceptions
def interesting(context, api_client, api_key, input_file, ip_address):
    """Report one or more IP addresses as "interesting"."""
    ip_addresses = get_ip_addresses(context, input_file, ip_address)
    results = [
        api_client.interesting(ip_address=ip_address) for ip_address in ip_addresses
    ]
    return results


@ip_lookup_command
@click.option("-v", "--verbose", count=True, help="Verbose output")
def ip(
    context,
    api_client,
    api_key,
    input_file,
    output_file,
    output_format,
    verbose,
    ip_address,
):
    """Query GreyNoise for all information on a given IP."""
    ip_addresses = get_ip_addresses(context, input_file, ip_address)
    results = [api_client.ip(ip_address=ip_address) for ip_address in ip_addresses]
    return results


@not_implemented_command
def pcap():
    """Get PCAP for a given IP address."""


@gnql_command
def query(
    context, api_client, api_key, input_file, output_file, output_format, verbose, query
):
    """Run a GNQL (GreyNoise Query Language) query."""
    queries = get_queries(context, input_file, query)
    results = [api_client.query(query=query) for query in queries]
    return results


@ip_lookup_command
def quick(
    context, api_client, api_key, input_file, output_file, output_format, ip_address
):
    """Quickly check whether or not one or many IPs are "noise"."""
    ip_addresses = get_ip_addresses(context, input_file, ip_address)
    results = []
    if ip_addresses:
        results.extend(api_client.quick(ip_addresses=ip_addresses))
    return results


@click.command()
@click.option("-k", "--api-key", required=True, help="Key to include in API requests")
@click.option("-t", "--timeout", type=click.INT, help="API client request timeout")
def setup(api_key, timeout):
    """Configure API key."""
    config = {"api_key": api_key}
    if timeout is None:
        config["timeout"] = DEFAULT_CONFIG["timeout"]
    else:
        config["timeout"] = timeout
    save_config(config)
    click.echo("Configuration saved to {!r}".format(CONFIG_FILE))


@not_implemented_command
def signature():
    """Submit an IDS signature to GreyNoise to be deployed to all GreyNoise nodes."""


@gnql_command
def stats(
    context, api_client, api_key, input_file, output_file, output_format, verbose, query
):
    """Get aggregate stats from a given GNQL query."""
    queries = get_queries(context, input_file, query)
    results = [api_client.stats(query=query) for query in queries]
    return results


@click.command()
def version():
    """Get version and OS information for your GreyNoise commandline installation."""
    click.echo(
        "greynoise {}\n"
        "  Python {}\n"
        "  {}\n".format(__version__, platform.python_version(), platform.platform())
    )
