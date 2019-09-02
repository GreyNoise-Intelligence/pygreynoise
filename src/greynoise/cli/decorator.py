"""CLI subcommand decorators.

Decorators used to add common functionality to subcommands.

"""
import functools
import os
import sys

import click

from greynoise.api import GreyNoise
from greynoise.cli.formatter import FORMATTERS
from greynoise.exceptions import RequestFailure
from greynoise.util import load_config


def echo_result(function):
    """Decorator that prints subcommand results correctly formatted.

    :param function: Subcommand that returns a result from the API.
    :type function: callable
    :returns: Wrapped function that prints subcommand results
    :rtype: callable

    """

    @functools.wraps(function)
    def wrapper(*args, **kwargs):
        result = function(*args, **kwargs)
        context = click.get_current_context()
        params = context.params
        output_format = params["output_format"]
        formatter = FORMATTERS[output_format]
        if isinstance(formatter, dict):
            # For the text formatter, there's a separate formatter for each subcommand
            formatter = formatter[context.info_name]

        output = formatter(result, params.get("verbose", False)).strip("\n")
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
    def wrapper(*args, **kwargs):
        try:
            return function(*args, **kwargs)
        except RequestFailure as exception:
            body = exception.args[1]
            click.echo("API error: {}".format(body["error"]))
            click.get_current_context().exit(-1)

    return wrapper


def pass_api_client(function):
    """Create API client form API key and pass it to subcommand.

    :param function: Subcommand that returns a result from the API.
    :type function: callable
    :returns: Wrapped function that prints subcommand results
    :rtype: callable

    """

    @functools.wraps(function)
    def wrapper(*args, **kwargs):
        context = click.get_current_context()
        api_key = context.params["api_key"]

        if api_key is None:
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

        api_client = GreyNoise(api_key)
        return function(api_client, *args, **kwargs)

    return wrapper
