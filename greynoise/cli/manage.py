#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Interact with the GreyNoise service."""

import os
import sys
from argparse import ArgumentParser
from greynoise import GNUtils
from greynoise import GNCli

__author__ = "Brandon Dixon"
__copyright__ = "Copyright, GreyNoise"
__credits__ = ["Brandon Dixon"]
__license__ = "MIT"
__maintainer__ = "Brandon Dixon"
__email__ = "brandon@9bplus.com"
__status__ = "BETA"

def main():



    """Run the core."""

    # Setup check before running a query
    # If running setup, or if config.json is missing, do something different
    if len(sys.argv) > 1 and sys.argv[1] == "setup":
        GNUtils.setup()

    # if I can't find your configuration
    elif not os.path.isfile(GNUtils.CONFIG_FILE):
        print(" Please run setup in order to establish your API key.\n Usage: greynoise setup -k <your API key>")
        exit()

    # User just wants to run a query - apply settings and run the GNCli
    elif len(sys.argv) == 2 and sys.argv[1] not in GNCli.flags_meta:
        if sys.argv[1] in GNCli.flags: #-- Here we do argparsing
        # Then you lack a necessary argument
            print(" Invalid request. Please specify a query or IP address.")
            exit()
        # otherwise default query
        else:
            outFile   = ""
            outFormat = "txt"
            queryType = "raw"
            rQuery    = sys.argv[1]
            verboseOut = False

            GNCli.runQuery(outFile,outFormat,queryType,rQuery,verboseOut)
            

    # Otherwise we do a query with flags 
    else:
        #verboseOut = False
        parser = ArgumentParser(description='GreyNoise - GreyNoise Commandline Interface')
        parser.add_argument('-f', '--file', dest='outFile',help='Output File')


        #verboseOut = False
        parser = ArgumentParser(description='GreyNoise - GreyNoise Commandline Interface')
        parser.add_argument('-f', '--file', dest='outFile',help='Output File')
        parser.add_argument('-o', '--output', dest='outFormat',help='Output Format')
        parser.add_argument('-q', '--query', dest='query',help='Query')
        parser.add_argument('-t', '--type', dest='queryType',help='Query Type')
        parser.add_argument('-v', '--verbose', action="store_true", help='Verbose Output')
        args      = parser.parse_args()
        outFile   = args.outFile
        outFormat = args.outFormat
        queryType = args.queryType
        rQuery    = args.query 
        verboseOut = args.verbose
        
        GNCli.runQuery(outFile,outFormat,queryType,rQuery,verboseOut)

if __name__ == '__main__':
    main()
