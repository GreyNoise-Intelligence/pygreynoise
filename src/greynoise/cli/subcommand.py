"""CLI subcommands."""

import functools

import click

from greynoise.cli.formatter import FORMATTERS
from greynoise.cli.parameter import ip_address_parameter, ip_addresses_parameter
from greynoise.exceptions import RequestFailure
from greynoise.util import CONFIG_FILE, save_config, validate_ip


class SubcommandNotImplemented(click.ClickException):
    """Exception used temporarily for subcommands that have not been implemented.

    :param subcommand_name: Name of the subcommand to display in the error message.
    :type subcommand_function: str

    """

    def __init__(self, subcommand_name):
        message = "{!r} subcommand is not implemented yet.".format(subcommand_name)
        super(SubcommandNotImplemented, self).__init__(message)


def echo_result(function):
    """Decorator that prints subcommand results correctly formatted.

    :param function: Subcommand that returns a result from the API.
    :type function: callable
    :returns: Wrapped function that prints subcommand results
    :rtype: callable

    """

    @functools.wraps(function)
    def wrapper(obj, *args, **kwargs):
        result = function(obj, *args, **kwargs)
        output_format = obj["output_format"]
        formatter = FORMATTERS[output_format]
        if isinstance(formatter, dict):
            # For the text formatter, there's a separate formatter for each subcommand
            formatter = formatter[obj["subcommand"]]

        output = formatter(result, obj["verbose"]).strip("\n")
        click.echo(output)

    return wrapper


def handle_exceptions(function):
    """Print error and exit on API client exception.

    :param function: Subcommand that returns a result from the API.
    :type function: callable
    :returns: Wrapped function that prints subcommand results
    :rtype: callable

    """

    @functools.wraps(function)
    def wrapper(obj, *args, **kwargs):
        try:
            return function(obj, *args, **kwargs)
        except RequestFailure as exception:
            body = exception.args[1]
            click.echo("API error: {}".format(body["error"]))
            click.get_current_context().exit(-1)

    return wrapper


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


@click.command()
def filter():
    """"Filter the noise from a log file, stdin, etc."""
    raise SubcommandNotImplemented("filter")


@click.command()
@click.pass_context
def help(context):
    """Show this message and exit."""
    click.echo(context.parent.get_help())


@click.command()
def interesting():
    """Report an IP as "interesting"."""
    raise SubcommandNotImplemented("interesting")


@click.command()
@click.argument("ip_address", callback=ip_address_parameter, required=False)
@click.pass_obj
@echo_result
@handle_exceptions
def ip(obj, ip_address):
    """Query GreyNoise for all information on a given IP."""
    obj["subcommand"] = "ip.context"
    api_client = obj["api_client"]
    input_file = obj["input_file"]
    results = []
    if input_file is not None:
        results.extend(
            api_client.ip(ip_address=line.strip())
            for line in input_file
            if validate_ip(line, strict=False)
        )
    if ip_address:
        results.append(api_client.ip(ip_address=ip_address))
    return results


@click.command()
def pcap():
    """Get PCAP for a given IP address."""
    raise SubcommandNotImplemented("pcap")


@click.command()
@click.argument("query", required=False)
@click.pass_obj
@echo_result
@handle_exceptions
def query(obj, query):
    """Run a GNQL (GreyNoise Query Language) query."""
    obj["subcommand"] = "gnql.query"
    api_client = obj["api_client"]
    input_file = obj["input_file"]
    results = []
    if input_file is not None:
        results.extend(api_client.query(query=line.strip()) for line in input_file)
    if query:
        results.append(api_client.query(query=query))
    return results


@click.command()
@click.argument("ip_address", callback=ip_addresses_parameter, nargs=-1)
@click.pass_obj
@echo_result
@handle_exceptions
def quick(obj, ip_address):
    """Quickly check whether or not one or many IPs are "noise"."""
    obj["subcommand"] = "ip.quick_check"
    api_client = obj["api_client"]
    input_file = obj["input_file"]

    if input_file is not None:
        ip_addresses = [
            line.strip() for line in input_file if validate_ip(line, strict=False)
        ]
    else:
        ip_addresses = []
    ip_addresses.extend(list(ip_address))

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


@click.command()
@click.argument("query", required=False)
@click.pass_obj
@echo_result
@handle_exceptions
def stats(obj, query):
    """Get aggregate stats from a given GNQL query."""
    obj["subcommand"] = "gnql.stats"
    api_client = obj["api_client"]
    input_file = obj["input_file"]
    results = []
    if input_file is not None:
        results.extend(api_client.stats(query=line.strip()) for line in input_file)
    if query:
        results.append(api_client.stats(query=query))
    return results


@click.command()
def version():
    """Get version and OS information for your GreyNoise commandline installation."""
    raise SubcommandNotImplemented("version")
