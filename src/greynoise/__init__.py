"""GreyNoise API client and tools."""

import logging

from greynoise.api import GreyNoise  # noqa

__author__ = "GreyNoise Intelligence"
__copyright__ = "Copyright, GreyNoise"
__credits__ = ["GreyNoise Intelligence"]
__license__ = "MIT"
__maintainer__ = "GreyNoise Intelligence"
__email__ = "hello@greynoise.io"
__status__ = "BETA"


logging.getLogger(__name__).addHandler(logging.NullHandler())
