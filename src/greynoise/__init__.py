"""GreyNoise API client and tools."""

from greynoise.__version__ import (  # noqa
    __author__,
    __copyright__,
    __credits__,
    __email__,
    __license__,
    __maintainer__,
    __status__,
    __version__,
)

USER_AGENT = "GreyNoise/{}".format(__version__)
PSYCHIC_USER_AGENT = "{} (psychic)".format(USER_AGENT)

from greynoise.api import GreyNoise  # noqa
from greynoise.greynoise_timeline import get_greynoise_timeline  # noqa
from greynoise.psychic import Psychic  # noqa
