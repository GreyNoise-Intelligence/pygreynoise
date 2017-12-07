import argparse
import json
from .api import GreyNoise, GreyNoiseError

def main():
    parser = argparse.ArgumentParser(description='Request GreyNoise')
    parser.add_argument('--list', '-l', help="List tags", action='store_true')
    parser.add_argument('--ip', '-i', help="Query an IP address")
    parser.add_argument('--tag', '-t', help="Query a tag")
    args = parser.parse_args()

    gn = GreyNoise()
    if args.list:
        res = gn.tags()
        print(json.dumps(res, indent=4, sort_keys=True))
    elif args.ip:
        try:
            res = gn.query_ip(args.ip)
        except GreyNoiseError:
            print("IP not found")
        else:
            print(json.dumps(res, indent=4, sort_keys=True))
    elif args.tag:
        try:
            res = gn.query_tag(args.tag)
        except GreyNoiseError:
            print("TAG does not exist")
        else:
            print(json.dumps(res, indent=4, sort_keys=True))

    else:
        parser.print_help()
