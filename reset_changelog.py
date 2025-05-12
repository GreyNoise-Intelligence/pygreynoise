# Reset changelog file to default content.
# This script is used by the release workflow.

import re

CHANGELOG_TEMPLATE = """\
=========
Changelog
=========

All notable changes to this project will be documented in this file.

The format is based on `Keep a Changelog \
<https://keepachangelog.com/en/1.0.0/>`_,
and this project adheres to `Semantic Versioning \
<https://semver.org/spec/v2.0.0.html>`_.

[Unreleased]
------------
"""

file_read_string = open(".bumpversion.cfg", "r").read()
match = re.search(r"current_version\s=\s(.*)", file_read_string)
ver = match.group(1)
print("current_ver = " + ver)

# validate changelog isn't updated already

file_read_string = open("CHANGELOG.rst", "r").read()
REGEX = "Version `dev`_"
match = re.search(REGEX, file_read_string)
if not match:
    print("CHANGELOG Needs Updating")
    with open("CHANGELOG.rst", "r+") as f:
        text = f.read()
        text = re.sub(
            "=========\nChangelog\n=========\n",
            (
                "=========\nChangelog\n=========\n\nVersion `dev`_\n================\n"
                "**Date**: unreleased\n\n* API client:\n"
            ),
            text,
        )
        f.seek(0)
        f.write(text)
        LINK_STRING = (
            ".. _`dev`: https://github.com/GreyNoise-Intelligence/pygreynoise/"
            "compare/v{}...HEAD"
        ).format(ver)
        f.write(LINK_STRING)
        f.truncate()
else:
    print("CHANGELOG")
