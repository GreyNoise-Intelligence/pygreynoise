"""GreyNoise command line Interface."""

import json
import sys

from xml.dom.minidom import parseString
from dicttoxml import dicttoxml

from greynoise.cli.parser import parse_arguments


def main(argv=None):
    """Entry point for the greynoise CLI.

    :param argv: Command line arguments
    :type: list

    """
    if argv is None:
        argv = sys.argv[1:]

    args = parse_arguments(argv)
    result = args.func(args)

    if result is None:
        return

    if args.format == "json":
        output = json.dumps(result)
    elif args.format == "xml":
        output = parseString(dicttoxml(result)).toprettyxml()

    print(output)
