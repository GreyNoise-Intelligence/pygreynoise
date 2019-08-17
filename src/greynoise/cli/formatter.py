"""Output formatters."""

import json
from xml.dom.minidom import parseString

from dicttoxml import dicttoxml


def json_formatter(result):
    """Format result as json."""
    return json.dumps(result, indent=4, sort_keys=True)


def xml_formatter(result):
    return parseString(dicttoxml(result)).toprettyxml()


def txt_formatter(result):
    return str(result)


FORMATTERS = {"json": json_formatter, "xml": xml_formatter, "txt": txt_formatter}
