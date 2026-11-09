"""Exception test cases."""

import pytest

from greynoise.exceptions import RateLimitError, RequestFailure, api_error_message


@pytest.mark.parametrize(
    "body, expected",
    (
        ({"message": "quota exceeded"}, "quota exceeded"),
        ({"error": "quota exceeded"}, "quota exceeded"),
        ({"message": "", "error": "quota exceeded"}, "quota exceeded"),
        ({"status": "error"}, None),
        ({}, None),
        ("plain text failure", "plain text failure"),
        ("  ", None),
        ("", None),
        (None, None),
    ),
)
def test_api_error_message(body, expected):
    """Error text is extracted from both JSON and plain text bodies."""
    assert api_error_message(body) == expected


class TestRateLimitError:
    """RateLimitError test cases."""

    def test_is_request_failure(self):
        """Rate limit errors stay catchable as request failures."""
        assert issubclass(RateLimitError, RequestFailure)

    def test_keeps_status_code_and_body(self):
        """Status code and response body are available on the exception."""
        body = {"message": "You have hit your daily quota", "status": "error"}
        error = RateLimitError(429, body)

        assert error.status_code == 429
        assert error.body == body
        assert error.message == "You have hit your daily quota"
        assert error.args == (429, body)

    def test_str_includes_api_message(self):
        """The message GreyNoise returned is part of the string form."""
        error = RateLimitError(429, {"message": "You have hit your daily quota"})

        assert str(error) == "rate limit exceeded (HTTP 429): You have hit your daily quota"

    def test_str_without_api_message(self):
        """A body without usable text still yields a readable message."""
        error = RateLimitError(429, {"status": "error"})

        assert str(error) == "rate limit exceeded (HTTP 429)"

    def test_defaults(self):
        """Instantiating without arguments keeps working."""
        error = RateLimitError()

        assert error.status_code == 429
        assert error.body is None
        assert error.message is None
        assert str(error) == "rate limit exceeded (HTTP 429)"
