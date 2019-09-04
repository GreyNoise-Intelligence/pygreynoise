"""Helper functions to reduce subcommand duplication."""

import sys

import click


def get_queries(context, input_file, query):
    """Get queries passed as argument or thourgh input file.

    :param context: Subcommand context
    :type context: click.Context
    :param input_file: Input file
    :type input_file: click.File | None
    :param query: GNQL query
    :type query: str | None

    """
    if input_file is None and not sys.stdin.isatty():
        input_file = sys.stdin

    if input_file is None and not query:
        click.echo(context.get_help())
        context.exit(-1)

    queries = []
    if input_file is not None:
        queries.extend([line.strip() for line in input_file])
    if query:
        queries.append(query)

    if not queries:
        output = [
            context.command.get_usage(context),
            (
                "Error: at least one query must be passed either as an argument "
                "(QUERY) or through the -i/--input_file option."
            ),
        ]
        click.echo("\n\n".join(output))
        context.exit(-1)

    return queries
