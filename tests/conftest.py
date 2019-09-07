import pytest

from greynoise.cli import configure_logging


@pytest.fixture(scope="session", autouse=True)
def configure_structlog():
    """Configure logging for test cases."""
    configure_logging()
