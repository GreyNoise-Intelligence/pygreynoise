#!/usr/bin/env python
"""Interact with the GreyNoise service."""
import base64
import json
import os
import logging
from argparse import ArgumentParser
from greynoise import GreyNoise
import sys


__author__ = "Brandon Dixon"
__copyright__ = "Copyright, GreyNoise"
__credits__ = ["Brandon Dixon"]
__license__ = "MIT"
__maintainer__ = "Brandon Dixon"
__email__ = "brandon@9bplus.com"
__status__ = "BETA"


CONFIG_PATH = os.path.expanduser('~/.config/greynoise')
CONFIG_FILE = os.path.join(CONFIG_PATH, 'config.json')
CONFIG_DEFAULTS = {'api_key': ''}


def main():
    """Run the core."""
    parser = ArgumentParser()
    subs = parser.add_subparsers(dest='cmd')
    setup_parser = subs.add_parser('setup')
    setup_parser.add_argument('-k', '--api-key', dest='api_key', required=True,
                              help='API key for GreyNoise.', type=str)
    args = parser.parse_args()

    if args.cmd == 'setup':
        if not os.path.exists(CONFIG_PATH):
            os.makedirs(CONFIG_PATH)
        if not os.path.exists(CONFIG_FILE):
            json.dump(CONFIG_DEFAULTS, open(CONFIG_FILE, 'w'), indent=4,
                      separators=(',', ': '))
        config = CONFIG_DEFAULTS
        config['api_key'] = args.api_key
        json.dump(config, open(CONFIG_FILE, 'w'), indent=4,
                  separators=(',', ': '))

    config = json.load(open(CONFIG_FILE))
    if config['api_key'] == '':
        raise Exception("Run setup before any other actions!")

    gn = GreyNoise(config['api_key'])
    raise NotImplementedError


if __name__ == '__main__':
    main()
