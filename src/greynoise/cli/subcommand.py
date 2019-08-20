"""CLI subcommands."""

import functools

import click

from greynoise.cli.formatter import FORMATTERS
from greynoise.cli.parameter import ip_address_parameter, ip_addresses_parameter
from greynoise.util import CONFIG_FILE, save_config


def echo_result(fn):
    """Decorator that prints subcommand results correctly formatted.

    :param fn: Subcommand that returns a result from the API.
    :type fn: callable
    :returns: Wrapped function that prints subcommand results
    :rtype: callable

    """

    @functools.wraps(fn)
    def wrapper(obj, *args, **kwargs):
        result = fn(obj, *args, **kwargs)
        output_format = obj["output_format"]
        if output_format in {"json", "csv"}:
            formatter = FORMATTERS[output_format]
        elif output_format == "txt":
            formatter = FORMATTERS[output_format][obj["subcommand"]]

        output = formatter(result).strip()
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
@click.argument("ip_address", callback=ip_address_parameter)
@click.pass_obj
@echo_result
def context(obj, ip_address):
    """Run IP context query."""
    obj["subcommand"] = "context"
    api_client = obj["api_client"]
    return api_client.get_context(ip_address=ip_address)


@ip.command()
@click.argument("ip_address", callback=ip_address_parameter)
@click.pass_obj
@echo_result
def quick_check(obj, ip_address):
    """Run IP quick check query."""
    obj["subcommand"] = "quick_check"
    api_client = obj["api_client"]
    return api_client.get_noise_status(ip_address=ip_address)


@ip.command()
@click.argument("ip_address", callback=ip_addresses_parameter, nargs=-1)
@click.pass_obj
@echo_result
def multi_quick_check(obj, ip_address):
    """Run IP multi quick check query."""
    obj["subcommand"] = "multi_quick_check"
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


@click.command()
@click.argument("query")
@click.pass_obj
@echo_result
def gnql(obj, query):
    """Run GNQL query."""
    obj["subcommand"] = "gnql"
    api_client = obj["api_client"]
    return api_client.run_query(query=query)


@click.command()
@click.argument("query")
@click.pass_obj
@echo_result
def stats(obj, query):
    """Run GNQL stats query."""
    obj["subcommand"] = "gnql_stats"
    api_client = obj["api_client"]
    return api_client.run_stats_query(query=query)
