"""Psychic client test cases."""

import csv
import ipaddress
from pathlib import Path
from unittest.mock import Mock

from greynoise import PSYCHIC_USER_AGENT
from greynoise.psychic import (
    Psychic,
    _mmdb_record_to_csv_row,
    _mmdb_record_value,
    _psychic_output_path,
    _write_mmdb_bytes_to_csv,
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


def test_download_bitmap_posts_model_and_date(tmp_path):
    """Psychic downloads bitmaps with model/date in the POST body."""
    psychic = Psychic(
        api_key="<api_key>",
        model=3,
        cache_dir=str(tmp_path),
        auto_download=False,
    )
    response = Mock(status_code=200, content=b"bitmap-data")
    response.raise_for_status = Mock()
    psychic.session.post = Mock(return_value=response)

    try:
        assert psychic._download_bitmap("2026-06-12") == b"bitmap-data"
        psychic.session.post.assert_called_once_with(
            psychic.PSYCHIC_BASE_URL,
            json={"model": "3", "date": "2026-06-12"},
            timeout=300,
        )
        response.raise_for_status.assert_called_once_with()
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
