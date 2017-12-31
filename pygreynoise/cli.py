import argparse
import json
from collections import Counter
from .api import GreyNoise, GreyNoiseError

def main():
    parser = argparse.ArgumentParser(description='Request GreyNoise')
    parser.add_argument('--list', '-l', help="List tags", action='store_true')
    parser.add_argument('--ip', '-i', help="Query an IP address")
    parser.add_argument('--tag', '-t', help="Query a tag")
    parser.add_argument('--format', '-f', help="Output format", choices=["csv", "json", "text", "asn"], default="text")
    args = parser.parse_args()

    gn = GreyNoise()
    if args.list:
        res = gn.tags()
        if args.format == "json":
            print(json.dumps(res, indent=4, sort_keys=True))
        else:
            for i in res:
                print(i)
    elif args.ip:
        try:
            res = gn.query_ip(args.ip)
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
    elif args.tag:
        try:
            res = gn.query_tag(args.tag)
        except GreyNoiseError:
            print("TAG does not exist")
        else:
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

    else:
        parser.print_help()
