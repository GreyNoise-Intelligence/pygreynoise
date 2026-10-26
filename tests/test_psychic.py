"""Psychic client test cases."""

import csv
import io
import ipaddress
import struct
from pathlib import Path
from unittest.mock import Mock, patch

from greynoise import PSYCHIC_USER_AGENT
from greynoise.exceptions import RateLimitError, RequestFailure
from greynoise.psychic import (
    Psychic,
    PsychicBitmapParser,
    _ensure_psychic_response_ok,
    _mmdb_record_to_csv_row,
    _mmdb_record_value,
    _psychic_output_path,
    _write_mmdb_bytes_to_csv,
    warn_unknown_psychic_model,
)


def test_psychic_user_agent_from_package(tmp_path):
    """Psychic uses the package-level User-Agent value."""
    psychic = Psychic(
        api_key="<api_key>",
        cache_dir=str(tmp_path),
        auto_download=False,
    )

    try:
        assert psychic.session.headers["User-Agent"] == PSYCHIC_USER_AGENT
    finally:
        psychic.session.close()


def test_psychic_applies_proxy_to_session(tmp_path):
    """Configured proxy is stored on the Psychic session for downloads."""
    psychic = Psychic(
        api_key="<api_key>",
        cache_dir=str(tmp_path),
        auto_download=False,
        proxy="http://proxy.example.com:8080",
    )

    try:
        assert psychic.session.proxies == {
            "http": "http://proxy.example.com:8080",
            "https": "http://proxy.example.com:8080",
        }
    finally:
        psychic.session.close()


def test_psychic_empty_proxy_leaves_session_proxies_unset(tmp_path):
    """Empty proxy must not set session.proxies or disable trust_env."""
    psychic = Psychic(
        api_key="<api_key>",
        cache_dir=str(tmp_path),
        auto_download=False,
        proxy="",
    )

    try:
        assert psychic.session.proxies == {}
        assert psychic.session.trust_env is True
    finally:
        psychic.session.close()


def test_psychic_uses_custom_api_server(tmp_path):
    """Psychic download URL is built from the configured api_server."""
    psychic = Psychic(
        api_key="<api_key>",
        cache_dir=str(tmp_path),
        auto_download=False,
        api_server="https://custom.greynoise.example/",
    )

    try:
        assert psychic.base_url == "https://custom.greynoise.example/v1/psychic"
        mock_response = Mock(status_code=200, content=b"bitmap")
        with patch.object(psychic.session, "post", return_value=mock_response) as mock_post:
            psychic._download_bitmap("2026-06-12")
            mock_post.assert_called_once()
            assert mock_post.call_args.args[0] == "https://custom.greynoise.example/v1/psychic"
    finally:
        psychic.session.close()


def test_warn_unknown_psychic_model(caplog):
    """Unknown Psychic models emit a warning instead of failing immediately."""
    with caplog.at_level("WARNING"):
        warn_unknown_psychic_model(4)
    assert "Current Psychic models are 1, 2, 3" in caplog.text
    assert "other model 4 will be attempted" in caplog.text


def test_psychic_accepts_unknown_model(tmp_path, caplog):
    """Psychic initialization accepts unknown models with a warning."""
    with caplog.at_level("WARNING"):
        psychic = Psychic(
            api_key="<api_key>",
            model=4,
            cache_dir=str(tmp_path),
            auto_download=False,
        )
    try:
        assert psychic.model == 4
        assert "other model 4 will be attempted" in caplog.text
    finally:
        psychic.session.close()


def test_ensure_psychic_response_ok_raises_request_failure():
    """Psychic HTTP helpers surface the API response body."""
    response = Mock(status_code=400)
    response.json.return_value = {"message": "invalid model"}
    try:
        _ensure_psychic_response_ok(response, "download bitmap")
        assert False, "expected RequestFailure"
    except RequestFailure as exc:
        assert exc.args[0] == 400
        assert exc.args[1] == {"message": "invalid model"}


def test_ensure_psychic_response_ok_raises_rate_limit_error():
    """A throttled Psychic request surfaces the API explanation."""
    response = Mock(status_code=429)
    response.json.return_value = {"message": "daily quota exhausted"}
    try:
        _ensure_psychic_response_ok(response, "download bitmap")
        assert False, "expected RateLimitError"
    except RateLimitError as exc:
        assert exc.status_code == 429
        assert exc.body == {"message": "daily quota exhausted"}
        assert str(exc) == "rate limit exceeded (HTTP 429): daily quota exhausted"


def test_lookup_ip_includes_psychic_file_date(tmp_path):
    """Psychic lookup results include the loaded bitmap file date."""
    psychic = Psychic(
        api_key="<api_key>",
        cache_dir=str(tmp_path),
        auto_download=False,
    )
    psychic._parser = Mock()
    psychic._parser.lookup_ip.return_value = {
        "ip": "1.2.3.4",
        "seen": False,
        "date": "2026-09-01",
    }
    psychic._last_loaded_date = "2026-09-01"

    try:
        result = psychic.lookup_ip("1.2.3.4")
        assert result["psychic_file_date"] == "2026-09-01"
        assert result["seen"] is False
    finally:
        psychic.session.close()


def test_load_generated_bitmap_for_days(tmp_path):
    """Psychic can generate and load a bitmap for a date range."""
    psychic = Psychic(
        api_key="<api_key>",
        model=3,
        cache_dir=str(tmp_path),
        auto_download=False,
    )
    psychic._generate_bitmap = Mock(return_value=b"generated-bitmap")
    psychic._parser = None

    try:
        with patch("greynoise.psychic.PsychicBitmapParser") as parser_cls:
            psychic.load_generated_bitmap_for_days(7)

        psychic._generate_bitmap.assert_called_once()
        start_date, end_date = psychic._generate_bitmap.call_args[0]
        assert start_date <= end_date
        parser_cls.assert_called_once_with(b"generated-bitmap")
        assert psychic._last_loaded_start_date == start_date
        assert psychic._last_loaded_end_date == end_date
        assert psychic._psychic_file_date_label() == f"{start_date} to {end_date}"
    finally:
        psychic.session.close()


def test_parse_metadata_uses_version0_mappings_for_multi_date_blocks():
    """Multi-date generated files keep version 0 IP mapping sections per date."""
    parser = PsychicBitmapParser.__new__(PsychicBitmapParser)
    parser.version = 2
    parser.verbose = False

    actor_count = 1
    actor = b"actor-a"
    tag_count = 0
    cve_count = 0
    ip_actor_count = 1
    ip_int = 0x01020304
    actor_idx = 0
    ip_tag_count = 0
    ip_cve_count = 0

    payload = b"".join(
        [
            struct.pack(">H", actor_count),
            struct.pack(">H", len(actor)),
            actor,
            struct.pack(">H", tag_count),
            struct.pack(">H", cve_count),
            struct.pack(">I", ip_actor_count),
            struct.pack(">I", ip_int),
            struct.pack(">H", actor_idx),
            struct.pack(">I", ip_tag_count),
            struct.pack(">I", ip_cve_count),
        ]
    )

    metadata = parser._parse_metadata(io.BytesIO(payload), ip_mapping_version=0)
    assert metadata["actors"] == ["actor-a"]
    assert metadata["ip_actors"][ip_int] == actor_idx


def test_download_bitmap_posts_model_and_date(tmp_path):
    """Psychic downloads bitmaps with model/date in the POST body."""
    psychic = Psychic(
        api_key="<api_key>",
        model=3,
        cache_dir=str(tmp_path),
        auto_download=False,
    )
    response = Mock(status_code=200, content=b"bitmap-data")
    psychic.session.post = Mock(return_value=response)

    try:
        assert psychic._download_bitmap("2026-06-12") == b"bitmap-data"
        psychic.session.post.assert_called_once_with(
            psychic.PSYCHIC_BASE_URL,
            json={"model": "3", "date": "2026-06-12"},
            timeout=300,
        )
    finally:
        psychic.session.close()


def test_download_mmdb_writes_file(tmp_path):
    """Psychic downloads MMDB data and writes it to the output directory."""
    psychic = Psychic(
        api_key="<api_key>",
        model=3,
        cache_dir=str(tmp_path),
        auto_download=False,
    )
    psychic._download_mmdb = Mock(return_value=b"mmdb-data")

    try:
        result = psychic.download_mmdb("2026-06-12", str(tmp_path))
        psychic._download_mmdb.assert_called_once_with("2026-06-12")
        assert result == str(tmp_path / "psychic_m3_2026-06-12.mmdb")
        assert (tmp_path / "psychic_m3_2026-06-12.mmdb").read_bytes() == b"mmdb-data"
    finally:
        psychic.session.close()


def test_download_bitmap_writes_file(tmp_path):
    """Psychic downloads bitmap data and writes it to the output directory."""
    psychic = Psychic(
        api_key="<api_key>",
        model=3,
        cache_dir=str(tmp_path),
        auto_download=False,
    )
    psychic._download_bitmap = Mock(return_value=b"bitmap-data")

    try:
        result = psychic.download_bitmap("2026-06-12", str(tmp_path))
        psychic._download_bitmap.assert_called_once_with("2026-06-12")
        assert result == str(tmp_path / "psychic_m3_2026-06-12.bin")
        assert (tmp_path / "psychic_m3_2026-06-12.bin").read_bytes() == b"bitmap-data"
    finally:
        psychic.session.close()


def test_psychic_output_path_treats_directory_as_parent(tmp_path):
    """Output paths without a file extension are treated as directories."""
    assert (
        _psychic_output_path(
            str(tmp_path),
            Path("/unused"),
            "psychic_m3_2026-06-17.csv",
        )
        == tmp_path / "psychic_m3_2026-06-17.csv"
    )

    assert (
        _psychic_output_path(
            str(tmp_path / "custom.csv"),
            Path("/unused"),
            "psychic_m3_2026-06-17.csv",
        )
        == tmp_path / "custom.csv"
    )


def test_download_csv_writes_to_directory(tmp_path, monkeypatch):
    """CSV export writes the default filename when given a directory path."""
    psychic = Psychic(
        api_key="<api_key>",
        model=3,
        cache_dir=str(tmp_path / "cache"),
        auto_download=False,
    )
    network = ipaddress.ip_network("1.2.3.4/32")
    record = {"ip": "1.2.3.4", "seen": True}

    class MockReader:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def __iter__(self):
            yield network, record

    class MockMaxMindDB:
        @staticmethod
        def open_database(_data):
            return MockReader()

    monkeypatch.setattr("greynoise.psychic.maxminddb", MockMaxMindDB())
    psychic._download_mmdb = Mock(return_value=b"mmdb-data")

    output_dir = tmp_path / "downloads"

    try:
        result = psychic._download_csv("2026-06-12", str(output_dir))
        assert result == str(output_dir / "psychic_m3_2026-06-12.csv")
        assert (output_dir / "psychic_m3_2026-06-12.csv").exists()
    finally:
        psychic.session.close()


def test_mmdb_record_to_csv_row_joins_list_fields():
    """MMDB list fields are serialized as semicolon-delimited CSV values."""
    network = ipaddress.ip_network("1.2.3.4/32")
    record = {
        "ip": "1.2.3.4",
        "date": "2026-06-12",
        "seen": True,
        "handshake_complete": False,
        "classification": "malicious",
        "actor": "unknown",
        "tags": ["Mirai", "Telnet Bruteforcer"],
        "cves": ["CVE-2021-1", "CVE-2021-2"],
    }
    columns = [
        "ip",
        "date",
        "seen",
        "3wh_completed",
        "classification",
        "actor",
        "tags",
        "cves",
    ]

    row = _mmdb_record_to_csv_row(network, record, columns)

    assert row == {
        "ip": "1.2.3.4",
        "date": "2026-06-12",
        "seen": "true",
        "3wh_completed": "false",
        "classification": "malicious",
        "actor": "unknown",
        "tags": "Mirai;Telnet Bruteforcer",
        "cves": "CVE-2021-1;CVE-2021-2",
    }


def test_mmdb_record_value_maps_handshake_complete_alias():
    """MMDB handshake_complete maps to the 3wh_completed CSV column."""
    record = {"handshake_complete": True}

    assert _mmdb_record_value(record, "3wh_completed") is True


def test_download_csv_writes_mmdb_records(tmp_path, monkeypatch):
    """Psychic downloads MMDB data and exports records to CSV."""
    psychic = Psychic(
        api_key="<api_key>",
        model=3,
        cache_dir=str(tmp_path),
        auto_download=False,
    )
    network = ipaddress.ip_network("1.2.3.4/32")
    record = {
        "ip": "1.2.3.4",
        "date": "2026-06-12",
        "seen": True,
        "handshake_complete": True,
        "classification": "malicious",
        "actor": "unknown",
        "tags": ["Mirai"],
        "cves": ["CVE-2021-1"],
    }

    class MockReader:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def __iter__(self):
            yield network, record

    class MockMaxMindDB:
        @staticmethod
        def open_database(_data):
            return MockReader()

    monkeypatch.setattr("greynoise.psychic.maxminddb", MockMaxMindDB())
    psychic._download_mmdb = Mock(return_value=b"mmdb-data")

    output_path = tmp_path / "psychic.csv"

    try:
        result = psychic._download_csv("2026-06-12", str(output_path))
        psychic._download_mmdb.assert_called_once_with("2026-06-12")
        assert result == str(output_path)

        with open(output_path, newline="", encoding="utf-8") as csv_file:
            rows = list(csv.DictReader(csv_file))

        assert rows == [
            {
                "ip": "1.2.3.4",
                "date": "2026-06-12",
                "seen": "true",
                "3wh_completed": "true",
                "classification": "malicious",
                "actor": "unknown",
                "tags": "Mirai",
                "cves": "CVE-2021-1",
            }
        ]
    finally:
        psychic.session.close()


def test_write_mmdb_bytes_to_csv_requires_maxminddb(tmp_path, monkeypatch):
    """CSV export fails clearly when maxminddb is unavailable."""
    monkeypatch.setattr("greynoise.psychic.maxminddb", None)

    try:
        _write_mmdb_bytes_to_csv(b"mmdb-data", Path(tmp_path / "out.csv"), 1)
    except ImportError as exc:
        assert "maxminddb is required" in str(exc)
    else:
        raise AssertionError("Expected ImportError when maxminddb is unavailable")
