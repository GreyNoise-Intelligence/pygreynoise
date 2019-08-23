"""CLI subcommands."""

import functools

import click
from click_default_group import DefaultGroup

from greynoise.cli.formatter import FORMATTERS
from greynoise.cli.parameter import ip_address_parameter, ip_addresses_parameter
from greynoise.util import CONFIG_FILE, save_config


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


@click.command()
@click.option("-k", "--api-key", required=True, help="Key to include in API requests")
def setup(api_key):
    """Configure API key."""
    config = {"api_key": api_key}
    save_config(config)
    click.echo("Configuration saved to {!r}".format(CONFIG_FILE))


@click.group()
def ip():
    """IP lookup."""


@ip.command()
@click.argument("ip_address", callback=ip_address_parameter, required=False)
@click.pass_obj
@echo_result
def context(obj, ip_address):
    """Run IP context query."""
    obj["subcommand"] = "ip.context"
    api_client = obj["api_client"]
    input_file = obj["input_file"]
    results = []
    if input_file is not None:
        results.extend(
            api_client.get_context(ip_address=line.strip()) for line in input_file
        )
    if query:
        results.append(api_client.get_context(ip_address=ip_address))
    return results


@ip.command()
@click.argument("ip_address", callback=ip_address_parameter)
@click.pass_obj
@echo_result
def quick_check(obj, ip_address):
    """Run IP quick check query."""
    obj["subcommand"] = "ip.quick_check"
    api_client = obj["api_client"]
    return api_client.get_noise_status(ip_address=ip_address)


@ip.command()
@click.argument("ip_address", callback=ip_addresses_parameter, nargs=-1)
@click.pass_obj
@echo_result
def multi_quick_check(obj, ip_address):
    """Run IP multi quick check query."""
    obj["subcommand"] = "ip.multi_quick_check"
    api_client = obj["api_client"]
    return api_client.get_noise_status_bulk(ip_addresses=list(ip_address))


@click.command()
@click.pass_obj
@echo_result
def actors(obj):
    """Run actors query."""
    obj["subcommand"] = "actors"
    api_client = obj["api_client"]
    return api_client.get_actors()


@click.group(cls=DefaultGroup, default="query", default_if_no_args=True)
def gnql():
    """GNQL queries."""


@gnql.command()
@click.argument("query", required=False)
@click.pass_obj
@echo_result
def query(obj, query):
    """Run GNQL query."""
    obj["subcommand"] = "gnql.query"
    api_client = obj["api_client"]
    input_file = obj["input_file"]
    results = []
    if input_file is not None:
        results.extend(api_client.run_query(query=line.strip()) for line in input_file)
    if query:
        results.append(api_client.run_query(query=query))
    return results


@gnql.command()
@click.argument("query", required=False)
@click.pass_obj
@echo_result
def stats(obj, query):
    """Run GNQL stats query."""
    obj["subcommand"] = "gnql.stats"
    api_client = obj["api_client"]
    input_file = obj["input_file"]
    results = []
    if input_file is not None:
        results.extend(
            api_client.run_stats_query(query=line.strip()) for line in input_file
        )
    if query:
        results.append(api_client.run_stats_query(query=query))
    return results
