# coding=utf-8
"""Output formatters."""

from __future__ import print_function

import json
from xml.dom.minidom import parseString

from dicttoxml import dicttoxml
from jinja2 import Environment, PackageLoader

JINJA2_ENV = Environment(loader=PackageLoader("greynoise.cli"))


def json_formatter(result, _verbose):
    """Format result as json."""
    return json.dumps(result, indent=4, sort_keys=True)


def xml_formatter(result, _verbose):
    return parseString(dicttoxml(result)).toprettyxml()


def get_location(metadata):
    """Get location from ip context metadata."""
    city = metadata["city"]
    country = metadata["country"]
    country_code = metadata["country_code"]

    location = []
    if city:
        location.append("{},".format(city))
    if country:
        location.append(country)
    if country_code:
        location.append("({})".format(country_code))
    return " ".join(location)


def ip_context_formatter(ip_context, verbose):
    """Convert IP context result into human-readable text."""
    if ip_context["seen"]:
        metadata = ip_context["metadata"]
        metadata["location"] = get_location(metadata)

    template = JINJA2_ENV.get_template("ip_context.txt.j2")
    return template.render(ip_context=ip_context, verbose=verbose)


def ip_quick_check_formatter(ip_quick_check, verbose):
    """Convert IP quick check result into human-readable text."""
    template = JINJA2_ENV.get_template("ip_quick_check.txt.j2")
    return template.render(ip_quick_check=ip_quick_check, verbose=verbose)


def ip_multi_quick_check_formatter(ip_multi_quick_check, verbose):
    """Convert IP multi quick check result into human-readable text."""
    template = JINJA2_ENV.get_template("ip_multi_quick_check.txt.j2")
    return template.render(ip_multi_quick_check=ip_multi_quick_check, verbose=verbose)


def gnql_query_formatter(gnql, verbose):
    """Convert GNQL query result into human-readable text."""
    if "data" in gnql:
        for ip_context in gnql["data"]:
            if ip_context["seen"]:
                metadata = ip_context["metadata"]
                metadata["location"] = get_location(metadata)

    template = JINJA2_ENV.get_template("gnql.txt.j2")
    return template.render(gnql=gnql, verbose=verbose)


def gnql_stats_formatter(gnql_stats, verbose):
    """Convert GNQL stats result into human-readable text."""
    template = JINJA2_ENV.get_template("gnql_stats.txt.j2")
    return template.render(gnql_stats=gnql_stats, verbose=verbose)


def actors_formatter(actors, verbose):
    """Convert actors result into human-readable text."""
    template = JINJA2_ENV.get_template("actors.txt.j2")
    return template.render(actors=actors, verbose=verbose)


FORMATTERS = {
    "json": json_formatter,
    "xml": xml_formatter,
    "txt": {
        "ip.context": ip_context_formatter,
        "ip.quick_check": ip_quick_check_formatter,
        "ip.multi_quick_check": ip_multi_quick_check_formatter,
        "gnql.query": gnql_query_formatter,
        "gnql.stats": gnql_stats_formatter,
        "actors": actors_formatter,
    },
}
