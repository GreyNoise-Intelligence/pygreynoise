"""CLI subcommand decorators.

Decorators used to add common functionality to subcommands.

"""

import functools
import logging

import click
from requests.exceptions import RequestException

from greynoise.api import APIConfig, GreyNoise
from greynoise.cli.formatter import FORMATTERS
from greynoise.cli.parameter import ip_addresses_parameter
from greynoise.exceptions import RequestFailure
from greynoise.util import load_config

LOGGER = logging.getLogger(__name__)


def _txt_formatter_command_key(context):
    """Build stable txt formatter dict key (e.g. recall-stats, callback-ip).

    Click 8.x does not expose ``command.parent`` on ``Command`` objects; nested
    paths come from ``Context.command_path`` (space-separated, prog name first).
    """
    raw = getattr(context, "command_path", None) or ""
    parts = raw.split()
    if len(parts) >= 2:
        return "-".join(parts[1:])
    return context.command.name


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
            formatter = formatter[_txt_formatter_command_key(context)]
        output = formatter(result, params.get("verbose", False)).strip("\n")
        click.echo(
            output, file=params.get("output_file", click.open_file("-", mode="w"))
        )

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
            status = exception.args[0]
            body = exception.args[1]
            if isinstance(body, dict):
                if "message" in body:
                    error_message = "API error: {}".format(body["message"])
                elif "error" in body:
                    error_message = "API error: {}".format(body["error"])
                elif not body:
                    error_message = "API error: {}".format(status)
                else:
                    error_message = "API error: {}".format(body)
            else:
                error_message = "API error: {}".format(body or status)
            LOGGER.error(error_message)
            click.get_current_context().exit(-1)
        except RequestException as exception:
            error_message = "API error: {}".format(exception)
            LOGGER.error(error_message)
            click.get_current_context().exit(-1)
        except ValueError as exception:
            error_message = "Validator error: {}".format(exception)
            LOGGER.error(error_message)
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
        api_key = context.params.get("api_key")
        offering = context.params.get("offering")
        config = load_config()

        if api_key is None:
            if not config["api_key"]:
                prog_name = context.parent.info_name
                click.echo(
                    "\nError: API key not found.\n\n"
                    "To fix this problem, please use any of the following methods "
                    "(in order of precedence):\n"
                    "- Pass it using the -k/--api-key option.\n"
                    "- Set it in the GREYNOISE_API_KEY environment variable.\n"
                    "- Run {!r} to save it to the configuration file.\n".format(
                        "{} setup".format(prog_name)
                    )
                )
                context.exit(-1)
            api_key = config["api_key"]

        if offering is None:
            if not config["offering"]:
                offering = "enterprise"
            else:
                offering = config["offering"]

        psychic = config.get("psychic", True)
        psychic_model = config.get("psychic_model")
        psychic_cache_dir = config.get("psychic_cache_dir")
        psychic_max_age_hours = config.get("psychic_max_age_hours", 1)

        api_config = APIConfig(
            api_key=api_key,
            api_server=config.get("api_server", "https://api.greynoise.io"),
            timeout=config.get("timeout", 60),
            proxy=config.get("proxy"),
            offering=offering,
            integration_name="cli",
            cache_max_size=config.get("cache_max_size", 1000000),
            cache_ttl=config.get("cache_ttl", 3600),
            use_cache=config.get("use_cache", True),
            psychic=psychic,
            psychic_model=psychic_model,
            psychic_cache_dir=psychic_cache_dir,
            psychic_max_age_hours=psychic_max_age_hours,
        )
        api_client = GreyNoise(api_config)
        return function(api_client, *args, **kwargs)

    return wrapper


def gnql_command(function):
    """Decorator that groups decorators common to gnql query and stats subcommands."""

    @click.command()
    @click.argument("query", required=False)
    @click.option("--size", "size", help="Max number of results to return")
    @click.option("--scroll", "scroll", help="Scroll token for pagination")
    @click.option("-k", "--api-key", help="Key to include in API requests")
    @click.option(
        "-O",
        "--offering",
        help="Which API offering to use, enterprise or community, "
        "defaults to enterprise",
    )
    @click.option("-i", "--input", "input_file", type=click.File(), help="Input file")
    @click.option(
        "-o", "--output", "output_file", type=click.File(mode="w"), help="Output file"
    )
    @click.option(
        "-f",
        "--format",
        "output_format",
        type=click.Choice(["json", "txt", "xml"]),
        default="txt",
        help="Output format",
    )
    @click.option("-v", "--verbose", count=True, help="Verbose output")
    @pass_api_client
    @click.pass_context
    @echo_result
    @handle_exceptions
    @functools.wraps(function)
    def wrapper(*args, **kwargs):
        return function(*args, **kwargs)

    return wrapper


def ip_lookup_command(function):
    """Decorator that groups decorators common to ip and quick subcommand."""

    @click.command()
    @click.argument("ip_address", callback=ip_addresses_parameter, nargs=-1)
    @click.option("-k", "--api-key", help="Key to include in API requests")
    @click.option(
        "-O",
        "--offering",
        help="Which API offering to use, enterprise or community, "
        "defaults to enterprise",
    )
    @click.option("-i", "--input", "input_file", type=click.File(), help="Input file")
    @click.option(
        "-o", "--output", "output_file", type=click.File(mode="w"), help="Output file"
    )
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
    @functools.wraps(function)
    def wrapper(*args, **kwargs):
        return function(*args, **kwargs)

    return wrapper


class SubcommandNotImplemented(click.ClickException):
    """Exception used temporarily for subcommands that have not been implemented.

    :param subcommand_name: Name of the subcommand to display in the error message.
    :type subcommand_function: str

    """

    def __init__(self, subcommand_name):
        message = "{!r} subcommand is not implemented yet.".format(subcommand_name)
        super(SubcommandNotImplemented, self).__init__(message)


def not_implemented_command(function):
    """Decorator that sends requests for not implemented commands."""

    @click.command()
    @pass_api_client
    @functools.wraps(function)
    def wrapper(api_client, *args, **kwargs):
        command_name = function.__name__
        try:
            api_client.not_implemented(command_name)
        except RequestFailure:
            raise SubcommandNotImplemented(command_name)

    return wrapper


def workspace_command(function):
    """Decorator that groups decorators common to workspace subcommands."""

    @click.command()
    @click.argument("workspace_id", required=True)
    @click.option("-k", "--api-key", help="Key to include in API requests")
    @click.option(
        "-O",
        "--offering",
        help="Which API offering to use, enterprise or community, "
        "defaults to enterprise",
    )
    @click.option("-i", "--input", "input_file", type=click.File(), help="Input file")
    @click.option(
        "-o", "--output", "output_file", type=click.File(mode="w"), help="Output file"
    )
    @click.option(
        "-f",
        "--format",
        "output_format",
        type=click.Choice(["json", "txt", "xml"]),
        default="txt",
        help="Output format",
    )
    @click.option("-v", "--verbose", count=True, help="Verbose output")
    @pass_api_client
    @click.pass_context
    @echo_result
    @handle_exceptions
    @functools.wraps(function)
    def wrapper(*args, **kwargs):
        return function(*args, **kwargs)

    return wrapper


def persona_command(function):
    """Decorator that groups decorators common to persona subcommands."""

    @click.command()
    @click.argument("persona_id", required=True)
    @click.option("-k", "--api-key", help="Key to include in API requests")
    @click.option(
        "-O",
        "--offering",
        help="Which API offering to use, enterprise or community, "
        "defaults to enterprise",
    )
    @click.option("-i", "--input", "input_file", type=click.File(), help="Input file")
    @click.option(
        "-o", "--output", "output_file", type=click.File(mode="w"), help="Output file"
    )
    @click.option(
        "-f",
        "--format",
        "output_format",
        type=click.Choice(["json", "txt", "xml"]),
        default="txt",
        help="Output format",
    )
    @click.option("-v", "--verbose", count=True, help="Verbose output")
    @pass_api_client
    @click.pass_context
    @echo_result
    @handle_exceptions
    @functools.wraps(function)
    def wrapper(*args, **kwargs):
        return function(*args, **kwargs)

    return wrapper


def cve_command(function):
    """Decorator that groups decorators common to cve subcommand."""

    @click.command()
    @click.argument("cve_id", required=True)
    @click.option("-k", "--api-key", help="Key to include in API requests")
    @click.option(
        "-O",
        "--offering",
        help="Which API offering to use, enterprise or community, "
        "defaults to enterprise",
    )
    @click.option("-i", "--input", "input_file", type=click.File(), help="Input file")
    @click.option(
        "-o", "--output", "output_file", type=click.File(mode="w"), help="Output file"
    )
    @click.option(
        "-f",
        "--format",
        "output_format",
        type=click.Choice(["json", "txt", "xml"]),
        default="txt",
        help="Output format",
    )
    @click.option("-v", "--verbose", count=True, help="Verbose output")
    @pass_api_client
    @click.pass_context
    @echo_result
    @handle_exceptions
    @functools.wraps(function)
    def wrapper(*args, **kwargs):
        return function(*args, **kwargs)

    return wrapper
