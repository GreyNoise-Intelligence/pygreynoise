# coding=utf-8
"""Output formatters."""

from __future__ import print_function

import functools
import json
import shutil

import ansimarkup
import colorama
from dict2xml import dict2xml
from jinja2 import Environment, PackageLoader, select_autoescape

JINJA2_ENV = Environment(
    loader=PackageLoader("greynoise.cli"),
    autoescape=select_autoescape(disabled_extensions=["txt.j2"]),
)

colorama.init()
DIM = "<dim>"
ANSI_MARKUP = ansimarkup.AnsiMarkup(
    tags={
        "header": ansimarkup.parse("<bold>"),
        "key": ansimarkup.parse("<blue>"),
        "value": ansimarkup.parse("<green>"),
        "noise": ansimarkup.parse("<light-yellow>"),
        "not-noise": ansimarkup.parse(DIM),
        "riot": ansimarkup.parse("<magenta>"),
        "not-riot": ansimarkup.parse(DIM),
        "malicious": ansimarkup.parse("<light-red>"),
        "unknown": ansimarkup.parse(DIM),
        "benign": ansimarkup.parse("<light-green>"),
        "suspicious": ansimarkup.parse("<yellow>"),
    }
)


def colored_output(function):
    """Decorator that converts ansi markup into ansi escape sequences.

    :param function: Function that will return text using ansi markup.
    :type function: callable
    :returns: Wrapped function that converts markup into escape sequences.
    :rtype: callable

    """

    @functools.wraps(function)
    def wrapper(*args, **kwargs):
        output = function(*args, **kwargs)
        return ANSI_MARKUP(output)

    return wrapper


def json_formatter(result, _verbose):
    """Format result as json."""
    if result is None or result == []:
        return "No results found"
    if isinstance(result, list) and "data" in result[0]:
        res = [json.dumps(record) for record in result[0]["data"]]
        output = "\n".join(res)
    else:
        output = json.dumps(result, indent=4, sort_keys=True)

    return output


def xml_formatter(result, _verbose):
    """Format result as xml."""
    xml_formatted = ""
    if result is None or result == []:
        return "No results found"
    if type(result) is list:
        xml_formatted = dict2xml({"item": result}, wrap="root", indent="\t")
    else:
        xml_formatted = dict2xml(result, wrap="root", indent="   ")

    # dict2xml does not add header, so add header manually
    xml_header = '<?xml version="1.0" ?>'
    return "{}\n{}".format(xml_header, xml_formatted)


def get_location(metadata):
    """Get location from ip context metadata."""
    city = metadata["source_city"]
    country = metadata["source_country"]
    country_code = metadata["source_country_code"]

    location = []
    if city:
        location.append("{},".format(city))
    if country:
        location.append(country)
    if country_code:
        location.append("({})".format(country_code))
    return " ".join(location)


@colored_output
def ip_context_formatter(results, verbose):
    """Convert IP context result into human-readable text."""
    for ip_context in results:
        if (
            "internet_scanner_intelligence" in ip_context
            and ip_context["internet_scanner_intelligence"]["found"]
        ):
            metadata = ip_context["internet_scanner_intelligence"]["metadata"]
            metadata["location"] = get_location(metadata)
            template = JINJA2_ENV.get_template("ip_context.txt.j2")
        else:
            template = JINJA2_ENV.get_template("ip_context.txt.j2")
    max_width, _ = shutil.get_terminal_size()
    return template.render(results=results, verbose=verbose, max_width=max_width)


@colored_output
def ip_quick_check_formatter(results, verbose):
    """Convert IP quick check result into human-readable text."""
    template = JINJA2_ENV.get_template("ip_quick_check.txt.j2")
    return template.render(results=results, verbose=verbose)


@colored_output
def ip_multi_context_formatter(results, verbose):
    """Convert IP multi context result into human-readable text."""
    template = JINJA2_ENV.get_template("ip_multi_context.txt.j2")
    return template.render(results=results, verbose=verbose)


@colored_output
def gnql_query_formatter(results, verbose):
    """Convert GNQL query result into human-readable text."""
    for result in results:
        if "data" in result:
            for ip_context in result["data"]:
                if (
                    "internet_scanner_intelligence" in ip_context
                    and "found" in ip_context["internet_scanner_intelligence"]
                ):
                    metadata = ip_context["internet_scanner_intelligence"]["metadata"]
                    metadata["location"] = get_location(metadata)

    template = JINJA2_ENV.get_template("gnql_query.txt.j2")
    return template.render(results=results, verbose=verbose)


@colored_output
def gnql_stats_formatter(results, verbose):
    """Convert GNQL stats result into human-readable text."""
    template = JINJA2_ENV.get_template("gnql_stats.txt.j2")
    max_width, _ = shutil.get_terminal_size()
    return template.render(results=results, verbose=verbose, max_width=max_width)


@colored_output
def analyze_formatter(result, verbose):
    """Conver analyze result into human-readable text."""
    template = JINJA2_ENV.get_template("analyze.txt.j2")
    max_width, _ = shutil.get_terminal_size()
    return template.render(result=result, verbose=verbose, max_width=max_width)


@colored_output
def riot_formatter(results, verbose):
    """Convert RIOT to human-readable text."""
    template = JINJA2_ENV.get_template("riot.txt.j2")
    max_width, _ = shutil.get_terminal_size()
    return template.render(results=results, verbose=verbose, max_width=max_width)


@colored_output
def similar_formatter(results, verbose):
    """Convert IP Sim to human-readable text."""
    template = JINJA2_ENV.get_template("similarity.txt.j2")
    max_width, _ = shutil.get_terminal_size()
    return template.render(results=results, verbose=verbose, max_width=max_width)


@colored_output
def timeline_formatter(results, verbose):
    """Convert Timeline to human-readable text."""
    template = JINJA2_ENV.get_template("timeline.txt.j2")
    max_width, _ = shutil.get_terminal_size()
    return template.render(results=results, verbose=verbose, max_width=max_width)


@colored_output
def timelinehourly_formatter(results, verbose):
    """Convert Timeline hourly/daily to human-readable text."""
    template = JINJA2_ENV.get_template("timelinehourly.txt.j2")
    max_width, _ = shutil.get_terminal_size()
    return template.render(results=results, verbose=verbose, max_width=max_width)


@colored_output
def sensoractivity_formatter(results, verbose):
    """Convert Sensor Activity to human-readable text."""
    template = JINJA2_ENV.get_template("sensoractivity.txt.j2")
    max_width, _ = shutil.get_terminal_size()
    return template.render(results=results, verbose=verbose, max_width=max_width)


@colored_output
def sensorlist_formatter(results, verbose):
    """Convert Sensor List to human-readable text."""
    template = JINJA2_ENV.get_template("sensorlist.txt.j2")
    max_width, _ = shutil.get_terminal_size()
    return template.render(results=results, verbose=verbose, max_width=max_width)


@colored_output
def personadetails_formatter(results, verbose):
    """Convert Persona Details to human-readable text."""
    template = JINJA2_ENV.get_template("personadetails.txt.j2")
    max_width, _ = shutil.get_terminal_size()
    return template.render(results=results, verbose=verbose, max_width=max_width)


@colored_output
def cvedetails_formatter(results, verbose):
    """Convert CVE Details to human-readable text."""
    template = JINJA2_ENV.get_template("cvedetails.txt.j2")
    max_width, _ = shutil.get_terminal_size()
    return template.render(results=results, verbose=verbose, max_width=max_width)


FORMATTERS = {
    "json": json_formatter,
    "xml": xml_formatter,
    "txt": {
        "analyze": analyze_formatter,
        "ip": ip_context_formatter,
        "quick": ip_quick_check_formatter,
        "query": gnql_query_formatter,
        "stats": gnql_stats_formatter,
        "riot": riot_formatter,
        "ip-multi": ip_multi_context_formatter,
        "similar": similar_formatter,
        "timeline": timeline_formatter,
        "timelinehourly": timelinehourly_formatter,
        "timelinedaily": timelinehourly_formatter,
        "sensor-activity": sensoractivity_formatter,
        "sensor-list": sensorlist_formatter,
        "persona-details": personadetails_formatter,
        "cve": cvedetails_formatter,
    },
}
