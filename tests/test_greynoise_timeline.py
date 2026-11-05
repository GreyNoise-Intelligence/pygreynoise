"""GreyNoise timeline helper proxy and request tests."""

from unittest.mock import Mock, patch

from greynoise.greynoise_timeline import fetch_field_timeline, fetch_tags_mapping


def test_fetch_tags_mapping_passes_proxy():
    """Tags mapping requests include the configured proxy."""
    mock_response = Mock()
    mock_response.raise_for_status = Mock()
    mock_response.json.return_value = {"tags": [{"id": "a", "name": "Tag A"}]}

    with patch("greynoise.greynoise_timeline.requests.get", return_value=mock_response) as mock_get:
        result = fetch_tags_mapping(
            "api-key",
            proxy="http://proxy.example.com",
        )
        assert result == {"a": "Tag A"}
        _, kwargs = mock_get.call_args
        assert kwargs["proxies"] == {
            "http": "http://proxy.example.com",
            "https": "http://proxy.example.com",
        }


def test_fetch_tags_mapping_omits_empty_proxy():
    """Empty proxy must not pass proxies={} to requests."""
    mock_response = Mock()
    mock_response.raise_for_status = Mock()
    mock_response.json.return_value = []

    with patch("greynoise.greynoise_timeline.requests.get", return_value=mock_response) as mock_get:
        fetch_tags_mapping("api-key", proxy="")
        _, kwargs = mock_get.call_args
        assert "proxies" not in kwargs


def test_fetch_field_timeline_passes_proxy():
    """Field timeline requests include the configured proxy."""
    mock_response = Mock()
    mock_response.raise_for_status = Mock()
    mock_response.json.return_value = {
        "metadata": {"field": "classification"},
        "results": [],
    }

    with patch("greynoise.greynoise_timeline.requests.get", return_value=mock_response) as mock_get:
        payload = fetch_field_timeline(
            "8.8.8.8",
            "classification",
            "api-key",
            proxy="http://proxy.example.com",
        )
        assert payload is not None
        _, kwargs = mock_get.call_args
        assert kwargs["proxies"] == {
            "http": "http://proxy.example.com",
            "https": "http://proxy.example.com",
        }


def test_fetch_field_timeline_omits_empty_proxy():
    """Empty proxy must not pass proxies={} to requests."""
    mock_response = Mock()
    mock_response.raise_for_status = Mock()
    mock_response.json.return_value = {
        "metadata": {"field": "classification"},
        "results": [],
    }

    with patch("greynoise.greynoise_timeline.requests.get", return_value=mock_response) as mock_get:
        fetch_field_timeline("8.8.8.8", "classification", "api-key", proxy=None)
        _, kwargs = mock_get.call_args
        assert "proxies" not in kwargs
