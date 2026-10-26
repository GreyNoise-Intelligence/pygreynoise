"""GreyNoise API client exceptions."""

from typing import Any, Optional


def api_error_message(body: Any) -> Optional[str]:
    """Return the error text the API sent in a response body, if any.

    :param body: Decoded JSON body or raw response text.
    :returns: Message from the body, or ``None`` when it carries no text.

    """
    if isinstance(body, dict):
        for key in ("message", "error"):
            value = body.get(key)
            if value:
                return str(value)
        return None

    if body is None:
        return None

    return str(body).strip() or None


class RequestFailure(Exception):
    """Exception to capture a failed request."""


class RateLimitError(RequestFailure):
    """API rate limit passed.

    The 429 response body explains *why* the request was throttled (plan
    limits, exhausted quota, ...), so it is kept on the exception instead of
    being discarded.

    """

    def __init__(self, status_code: int = 429, body: Any = None) -> None:
        super().__init__(status_code, body)
        self.status_code = status_code
        self.body = body
        self.message = api_error_message(body)

    def __str__(self) -> str:
        summary = "rate limit exceeded (HTTP {})".format(self.status_code)
        if self.message:
            return "{}: {}".format(summary, self.message)
        return summary


class NotFound(Exception):
    """Requested resource was not found."""
