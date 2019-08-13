#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Interact with the GreyNoise service."""

import os
import sys

from argparse import ArgumentParser
from greynoise.gnutils import GNUtils
from greynoise.gncli import GNCli

__author__ = "GreyNoise Intelligence"
__copyright__ = "Copyright, GreyNoise"
__credits__ = ["GreyNoise Intelligence"]
__license__ = "MIT"
__maintainer__ = "GreyNoise Intelligence"
__email__ = "hello@greynoise.io"
__status__ = "BETA"


def main():

    """Run the core."""

    # Setup check before running a query
    # If running setup, or if config.json is missing, do something different
    if len(sys.argv) > 1 and sys.argv[1] == "setup":
        GNUtils.setup()

    # if I can't find your configuration
    elif not os.path.isfile(GNUtils.CONFIG_FILE):
        print(
            " Please run setup in order to establish your API key.\n"
            " Usage: greynoise setup -k <your API key>"
        )
        exit()

    # User just wants to run a query - apply settings and run the GNCli
    elif len(sys.argv) == 2 and sys.argv[1] not in GNCli.flags_meta:
        if sys.argv[1] in GNCli.flags:  # -- Here we do argparsing
            # Then you lack a necessary argument
            print(" Invalid request. Please specify a query or IP address.")
            exit()
        # otherwise default query
        else:
            out_file = ""
            out_format = "txt"
            query_type = "raw"
            r_query = sys.argv[1]
            verbose_out = False

            GNCli.run_query(out_file, out_format, query_type, r_query, verbose_out)

    # Otherwise we do a query with flags
    else:
        parser = ArgumentParser(
            description="GreyNoise - GreyNoise Commandline Interface"
        )
        parser.add_argument("-f", "--file", dest="out_file", help="Output File")

        parser = ArgumentParser(
            description="GreyNoise - GreyNoise Commandline Interface"
        )
        parser.add_argument("-f", "--file", dest="out_file", help="Output File")
        parser.add_argument("-o", "--output", dest="out_format", help="Output Format")
        parser.add_argument("-q", "--query", dest="query", help="Query")
        parser.add_argument("-t", "--type", dest="query_type", help="Query Type")
        parser.add_argument(
            "-v", "--verbose", action="store_true", help="Verbose Output"
        )
        args = parser.parse_args()
        out_file = args.out_file
        out_format = args.out_format
        query_type = args.query_type
        r_query = args.query
        verbose_out = args.verbose

        GNCli.run_query(out_file, out_format, query_type, r_query, verbose_out)


if __name__ == "__main__":
    main()
