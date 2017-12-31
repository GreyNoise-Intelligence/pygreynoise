import argparse
import os
import json
import subprocess
from collections import Counter
from .api import GreyNoise, GreyNoiseError

def main():
    parser = argparse.ArgumentParser(description='Request GreyNoise')
    subparsers = parser.add_subparsers(help='Subcommand')
    parser_a = subparsers.add_parser('ip', help='Request info on an IP')
    parser_a.add_argument('IP',  help='IP')
    parser_a.add_argument('--format', '-f', help="Output format", choices=["csv", "json", "text"], default="text")
    parser_a.set_defaults(subcommand='ip')
    parser_b = subparsers.add_parser('list', help='List GreyNoise Tags')
    parser_b.add_argument('--format', '-f', help="Output format", choices=["json", "text"], default="text")
    parser_b.set_defaults(subcommand='list')
    parser_c = subparsers.add_parser('tag', help='Query data for a tag')
    parser_c.add_argument('TAG',  help='Tag')
    parser_c.add_argument('--format', '-f', help="Output format", choices=["csv", "json", "text", "asn"], default="text")
    parser_c.set_defaults(subcommand='tag')
    parser_d = subparsers.add_parser('config', help='Configure key file')
    parser_d.set_defaults(subcommand='config')
    args = parser.parse_args()

    gn = GreyNoise()
    if 'subcommand' in args:
        if args.subcommand == "list":
            res = gn.tags()
            if args.format == "json":
                print(json.dumps(res, indent=4, sort_keys=True))
            else:
                for i in res:
                    print(i)
        elif args.subcommand == "ip":
            try:
                res = gn.query_ip(args.IP)
            except GreyNoiseError:
                print("IP not found")
            else:
                if args.format == "json":
                    print(json.dumps(res, indent=4, sort_keys=True))
                elif args.format == "text":
                    r = res[0]
                    print("[+] %s - %s" % (r["metadata"]["asn"], r["metadata"]["org"]))
                    if r["metadata"]["os"]:
                        print("[+] %s" % r["metadata"]["os"])
                    if r["metadata"]["rdns"]:
                        print("[+] %s" % r["metadata"]["rdns"])
                    if r["metadata"]["tor"]:
                        print("[+] Tor relay")
                    print("[+] Detection: %s" % ", ".join(set([i["name"] for i in res])))
                else:
                    print("Tag;Category;Confidence;Intention;First Seen;Last Seen;ASN;Datacenter;Link;Org;OS;RDNS;Tor")
                    for r in res:
                        print("%s;%s;%s;%s;%s;%s;%s;%s;%s;%s;%s;%s;%s" % (
                                r["name"],
                                r["category"],
                                r["confidence"],
                                r["intention"],
                                r["first_seen"],
                                r["last_updated"],
                                r["metadata"]["asn"],
                                r["metadata"]["datacenter"],
                                r["metadata"]["link"],
                                r["metadata"]["os"],
                                r["metadata"]["org"],
                                r["metadata"]["rdns"],
                                r["metadata"]["tor"]
                            )
                        )
        elif args.subcommand == "tag":
            try:
                res = gn.query_tag(args.TAG)
            except GreyNoiseError:
                print("TAG does not exist")

            if args.format == "json":
                print(json.dumps(res, indent=4, sort_keys=True))
            elif args.format == "text":
                for r in res:
                    if r["metadata"]["rdns"] != "":
                        print("[+] %s (%s - %s - %s - %s)" % (
                                r["ip"],
                                r["metadata"]["asn"],
                                r["metadata"]["org"],
                                r["metadata"]["rdns"],
                                r["metadata"]["os"]
                            )
                        )
                    else:
                        print("[+] %s (%s - %s - %s)" % (
                                r["ip"],
                                r["metadata"]["asn"],
                                r["metadata"]["org"],
                                r["metadata"]["os"]
                            )
                        )
            elif args.format == "asn":
                asn_names = dict([(r["metadata"]["asn"], r["metadata"]["org"]) for r in res])
                asns = [r["metadata"]["asn"] for r in res]
                asn_count = Counter(asns)
                for r in asn_count.most_common():
                    if r[0] == "":
                        print("Unknown - %i entries" % r[1])
                    else:
                        print("%s %s - %i entries" % (r[0], asn_names[r[0]], r[1]))
            else:
                print("IP;Tag;Category;Confidence;Intention;First Seen;Last Seen;ASN;Datacenter;Link;Org;OS;RDNS;Tor")
                for r in res:
                    print("%s;%s;%s;%s;%s;%s;%s;%s;%s;%s;%s;%s;%s;%s" % (
                            r["ip"],
                            r["name"],
                            r["category"],
                            r["confidence"],
                            r["intention"],
                            r["first_seen"],
                            r["last_updated"],
                            r["metadata"]["asn"],
                            r["metadata"]["datacenter"],
                            r["metadata"]["link"],
                            r["metadata"]["os"],
                            r["metadata"]["org"],
                            r["metadata"]["rdns"],
                            r["metadata"]["tor"]
                        )
                    )
        elif args.subcommand == "config":
            config_path = os.path.join(os.path.expanduser("~"), ".greynoise")
            if not os.path.isfile(config_path):
                with open(config_path, 'w') as f:
                    f.write("[GreyNoise]\nkey:")
                    f.close()
            subprocess.call(os.environ.get('EDITOR', 'vi') + ' ' + config_path, shell=True)

        else:
            parser.print_help()
    else:
        parser.print_help()
