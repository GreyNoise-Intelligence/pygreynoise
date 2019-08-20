# coding=utf-8
"""Output formatters."""

from __future__ import print_function

import json
import pydoc
from collections import OrderedDict
from xml.dom.minidom import parseString

from dicttoxml import dicttoxml


def json_formatter(result):
    """Format result as json."""
    return json.dumps(result, indent=4, sort_keys=True)


def xml_formatter(result):
    return parseString(dicttoxml(result)).toprettyxml()


# For output
CONTEXTFIELDS = OrderedDict(
    [
        ("ip", "IP"),
        ("classification", "Classification"),
        ("first_seen", "First seen"),
        ("last_seen", "Last seen"),
        ("actor", "Actor"),
        ("tags", "Tags"),
    ]
)
METADATAFIELDS = {
    "organization": "Organization",
    "rdns": "rDNS",
    "asn": "ASN",
    "tor": "Tor",
    "os": "OS",
    "category": "Category",
}


def txt_ip(results, verbose):
    try:
        if "error" in results:
            print(" Error: %s" % results["error"])
        # quick scan fields
        elif "noise" in results:
            if results["noise"]:
                print(" %s is classified as NOISE." % results["ip"])
            elif not results["noise"]:
                print(" %s is classified as NOT NOISE." % results["ip"])
        # context/gnql fields - called for each result in the list when used
        # with multi-searches
        elif "seen" in results or "count" in results:
            if results["seen"] or ("count" in results and results["count"] > 0):
                print(" " * 10 + "OVERVIEW:")
                print(" " + "-" * 28)
                for field in CONTEXTFIELDS:
                    print(" %s: %s" % (CONTEXTFIELDS[field], results[field]))
                print()
                print(" " * 10 + "METADATA:")
                print(" " + "-" * 28)
                # Complete location info is not always available, so
                # concatenate whatever info there is.
                if results["metadata"]["city"]:
                    city = "%s, " % results["metadata"]["city"]
                else:
                    city = ""
                if results["metadata"]["country"]:
                    country = results["metadata"]["country"]
                else:
                    country = "Unknown Country"
                if results["metadata"]["country_code"]:
                    country_code = " (%s)" % results["metadata"]["country_code"]
                else:
                    country_code = ""
                print(" Location: %s%s%s" % (city, country, country_code))
                # the rest of the metadata can be looped thru
                for field in METADATAFIELDS:
                    try:
                        if results["metadata"][field]:
                            if field == "tor":  # the only non string..
                                print("  Tor: %b" % results["metadata"][field])
                            elif results["metadata"][field]:
                                print(
                                    " %s: %s"
                                    % (
                                        METADATAFIELDS[field],
                                        results["metadata"][field],
                                    )
                                )
                    except Exception:
                        continue
                print()
                print(" " * 10 + "RAW DATA:")
                print(" " + "-" * 28)
                if results["raw_data"]["scan"]:
                    if (len(results["raw_data"]["scan"]) < 20) or verbose:
                        for item in results["raw_data"]["scan"]:
                            try:
                                print(
                                    " Port/Proto: %s/%s"
                                    % (item["port"], item["protocol"])
                                )
                            except Exception:
                                continue
                    else:
                        counter = 0
                        for item in results["raw_data"]["scan"]:
                            try:
                                print(
                                    " Port/Proto: %s/%s"
                                    % (item["port"], item["protocol"])
                                )
                                counter += 1
                                if counter == 20:
                                    break  # can make this nicer
                            except Exception:
                                continue
                        print(
                            " Showing results 1 - 20 of %s. "
                            "Run again with -v for full output."
                            % len(results["raw_data"]["scan"])
                        )
                if results["raw_data"]["web"]:
                    print()
                    print(" [Paths]")
                    if not results["raw_data"]["web"]["paths"]:
                        print(" None found.")
                    else:
                        if len(results["raw_data"]["web"]["paths"]) < 20 or verbose:
                            for path in results["raw_data"]["web"]["paths"]:
                                try:
                                    print(" %s" % path)
                                except Exception:
                                    continue
                        else:
                            for index in range(20):
                                try:
                                    print(
                                        " %s"
                                        % results["raw_data"]["web"]["paths"][index]
                                    )
                                except Exception:
                                    continue
                            print(
                                " Showing results 1 - 20 of %s. "
                                "Run again with -v for full output."
                                % len(results["raw_data"]["web"]["paths"])
                            )
                if results["raw_data"]["ja3"]:
                    print("[JA3]")
                    if not results["raw_data"]["ja3"]:
                        print("None found.")
                    else:
                        for i in results["raw_data"]["ja3"]:
                            try:
                                print(
                                    " Port: %s Fingerprint: %s"
                                    % (i["port"], i["fingerprint"])
                                )
                            except Exception:
                                continue
                print()
            else:
                print(
                    "%s has not been seen in scans in the past 30 days." % results["ip"]
                )
    except Exception as e:
        print("Error converting output!")
        print(e)


def make_txt(results, query_type, verbose):
    try:
        if query_type == "bulk" or query_type == "date":
            formatted = ""
            maxcount = 6  # IPs per line - TODO: allow user to set
            count = 0
            # Concatenate IPs into a string of readable columns, variable width
            for ip in results["noise_ips"]:
                if count == 0:
                    # adds spacing to the left of the first IP printed on each line.
                    ip = "  " + ip
                formatted = formatted + (ip + " " * (18 - len(ip)))
                count += 1
                if count == maxcount:
                    count = 0
                    formatted = formatted + "\n"
            # result is paginated
            return pydoc.pager(formatted)
        if query_type == "quick" or query_type == "context":
            txt_ip(results, verbose)
        if query_type == "raw" or not query_type:
            if "data" in results:
                counter = 1
                for entry in results["data"]:
                    heading = "result %i of %i" % (counter, len(results["data"]))
                    # total number of spaces needed for padding
                    spacing = 27 - len(heading)
                    # if odd number, extra space should go in front.
                    if (27 - len(heading)) % 2 != 0:
                        leading_spaces = int((spacing + 1) / 2)
                        trailing_spaces = leading_spaces - 1
                        heading = (
                            " " * (leading_spaces) + heading + " " * trailing_spaces
                        )
                    else:
                        heading = (
                            " " * int(spacing / 2) + heading + " " * int(spacing / 2)
                        )
                    # print title bar for each numbered result
                    # (doesnt work well in some environments)
                    print(
                        " ┌───────────────────────────┐\n"
                        " │%s│\n"
                        " └───────────────────────────┘" % heading
                    )
                    print()
                    txt_ip(entry, verbose)
                    print()
                    print()
                    counter += 1
            else:
                print(" No results found.")
    except Exception as e:
        print(" Error making text output!")
        print(e)


FORMATTERS = {"json": json_formatter, "xml": xml_formatter}
