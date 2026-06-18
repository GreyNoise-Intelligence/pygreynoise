"""
Psychic bitmap module for high-performance IP lookups.

This module provides offline bitmap functionality for GreyNoise data,
allowing for extremely fast IP lookups without API calls.
"""

import csv
import io
import ipaddress
import logging
import os
import struct
import tempfile
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, BinaryIO, Dict, List, Optional, Set, Tuple, Union

import requests

try:
    import maxminddb
except ImportError:
    maxminddb = None  # type: ignore[assignment]

from greynoise import PSYCHIC_USER_AGENT

logger = logging.getLogger(__name__)

MMDB_CSV_COLUMNS = {
    1: ["ip", "seen"],
    2: ["ip", "seen", "3wh_completed", "classification"],
    3: [
        "ip",
        "date",
        "seen",
        "3wh_completed",
        "classification",
        "actor",
        "tags",
        "cves",
    ],
}


MMDB_FIELD_ALIASES = {
    "3wh_completed": ("3wh_completed", "handshake_complete"),
}


def _mmdb_record_value(record: Dict[str, Any], column: str) -> Any:
    """Return a CSV column value from an MMDB record."""
    keys = MMDB_FIELD_ALIASES.get(column, (column,))
    for key in keys:
        if key in record:
            return record[key]

    classifications = record.get("classifications")
    if isinstance(classifications, dict):
        for key in keys:
            if key in classifications:
                return classifications[key]

    return None


def _mmdb_value_to_csv(value: Any) -> str:
    """Convert an MMDB record value to a CSV-safe string."""
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, list):
        return ";".join(str(item) for item in value)
    return str(value)


def _mmdb_record_to_csv_row(
    network: Union[ipaddress.IPv4Network, ipaddress.IPv6Network],
    record: Dict[str, Any],
    columns: List[str],
) -> Dict[str, str]:
    """Build a CSV row from an MMDB network/record pair."""
    ip = record.get("ip") or str(network.network_address)
    row = {}
    for column in columns:
        if column == "ip":
            row[column] = str(ip)
        else:
            row[column] = _mmdb_value_to_csv(_mmdb_record_value(record, column))
    return row


def _psychic_output_path(
    output_path: Optional[str],
    default_directory: Path,
    filename: str,
) -> Path:
    """Resolve a psychic output path from a directory or file path."""
    if output_path is None:
        directory = default_directory
    else:
        path = Path(output_path)
        if path.suffix in {".csv", ".mmdb"}:
            path.parent.mkdir(parents=True, exist_ok=True)
            return path
        directory = path

    directory.mkdir(parents=True, exist_ok=True)
    return directory / filename


def _write_mmdb_bytes_to_csv(mmdb_data: bytes, output_path: Path, model: int) -> None:
    """Iterate an MMDB file and write psychic records to CSV."""
    if maxminddb is None:
        raise ImportError("maxminddb is required for Psychic CSV export. " "Install it with: pip install maxminddb")

    if model not in MMDB_CSV_COLUMNS:
        raise ValueError("Model must be 1, 2, or 3")

    columns = MMDB_CSV_COLUMNS[model]
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with tempfile.NamedTemporaryFile(suffix=".mmdb", delete=False) as mmdb_file:
        mmdb_path = mmdb_file.name
        mmdb_file.write(mmdb_data)

    try:
        with maxminddb.open_database(mmdb_path) as reader:
            with open(output_path, "w", newline="", encoding="utf-8") as csv_file:
                writer = csv.DictWriter(csv_file, fieldnames=columns)
                writer.writeheader()
                for network, record in reader:
                    if not record:
                        continue
                    writer.writerow(_mmdb_record_to_csv_row(network, record, columns))
    finally:
        os.unlink(mmdb_path)


class RoaringBitmapReader:
    """
    Pure Python implementation of Roaring Bitmap reader for the
    standard serialized format.
    """

    SERIAL_COOKIE_NO_RUNCONTAINER = 12346  # 0x303a
    SERIAL_COOKIE = 12347  # 0x303b
    NO_OFFSET_THRESHOLD = 4

    def __init__(self):
        self.containers = {}  # key -> set of values
        self.num_containers = 0

    def read_from(self, file: BinaryIO) -> None:
        """Read a standard serialized Roaring bitmap from file."""
        self.containers.clear()

        # Read cookie (4 bytes)
        cookie_data = file.read(4)
        if len(cookie_data) < 4:
            return  # Empty bitmap

        cookie = struct.unpack("<I", cookie_data)[0]

        if cookie not in [self.SERIAL_COOKIE_NO_RUNCONTAINER, self.SERIAL_COOKIE]:
            raise ValueError(f"Invalid Roaring bitmap cookie: {cookie} (0x{cookie:08x})")

        if cookie == self.SERIAL_COOKIE_NO_RUNCONTAINER:
            # Cookie followed by container count (4 bytes)
            count_data = file.read(4)
            if len(count_data) < 4:
                raise ValueError("Invalid bitmap: missing container count")
            self.num_containers = struct.unpack("<I", count_data)[0]
        else:
            # For SERIAL_COOKIE, the upper 16 bits contain (num_containers - 1)
            # This case is not used by psychic2 based on our analysis
            raise NotImplementedError("Run containers format not implemented")

        if self.num_containers == 0:
            return  # Empty bitmap

        # Read key-cardinality pairs (they are interleaved, not separate arrays)
        keys = []
        cardinalities = []
        for _ in range(self.num_containers):
            # Read key
            key_data = file.read(2)
            if len(key_data) < 2:
                raise ValueError("Insufficient data for key")
            keys.append(struct.unpack("<H", key_data)[0])

            # Read cardinality (stored as card-1)
            card_data = file.read(2)
            if len(card_data) < 2:
                raise ValueError("Insufficient data for cardinality")
            cardinalities.append(struct.unpack("<H", card_data)[0] + 1)

        # Read offsets if present
        # Check if we need to skip offsets
        if self.num_containers >= self.NO_OFFSET_THRESHOLD:
            # Skip offsets - we don't use them, just read containers sequentially
            skip_size = self.num_containers * 4
            file.seek(skip_size, 1)  # Skip forward

        # Read container data sequentially
        for i in range(self.num_containers):
            key = keys[i]
            cardinality = cardinalities[i]

            # Determine container type based on cardinality
            if cardinality <= 4096:
                # Array container
                values = set()
                for _ in range(cardinality):
                    val_data = file.read(2)
                    if len(val_data) < 2:
                        raise ValueError(f"Insufficient data for array container {i}")
                    values.add(struct.unpack("<H", val_data)[0])
                self.containers[key] = values
            else:
                # Bitmap container (8KB = 8192 bytes = 1024 uint64s)
                bitmap_data = file.read(8192)
                if len(bitmap_data) < 8192:
                    raise ValueError(f"Insufficient data for bitmap container {i}")

                # Convert bitmap to set of values
                values = set()
                for j in range(1024):  # 1024 uint64 values
                    word = struct.unpack("<Q", bitmap_data[j * 8 : (j + 1) * 8])[0]
                    if word != 0:
                        # Extract set bits
                        for bit in range(64):
                            if word & (1 << bit):
                                values.add(j * 64 + bit)

                self.containers[key] = values

    def contains(self, value: int) -> bool:
        """Check if a value is in the bitmap."""
        high = value >> 16
        low = value & 0xFFFF

        if high not in self.containers:
            return False

        return low in self.containers[high]

    def get_all_values(self) -> Set[int]:
        """Get all values in the bitmap as a set."""
        result = set()
        for key, values in self.containers.items():
            high = key << 16
            for low in values:
                result.add(high | low)
        return result


class PsychicBitmapParser:
    """Parser for Psychic bitmap files."""

    def __init__(self, data: bytes, verbose: bool = False):
        self.data = data
        self.verbose = verbose
        self.header = None
        self.model = None
        self.bitmaps = {}
        self.metadata = {}
        self.date_bitmaps = {}  # For multi-date format: date -> bitmaps
        self.date_metadata = {}  # For model 3 multi-date format: date -> metadata
        self._parse_data()

    def _log(self, message: str):
        """Log message if verbose mode is enabled."""
        if self.verbose:
            logger.debug(f"[PSYCHIC] {message}")

    def _parse_header(self, data: bytes, offset: int = 0) -> Tuple[Dict[str, Any], int]:
        """Parse the 34-byte psychic2 header."""
        if len(data) < offset + 34:
            raise ValueError("Invalid header: insufficient data")

        header_data = data[offset : offset + 34]

        magic = header_data[0:2]
        if magic != b"GN":
            raise ValueError(f"Invalid magic bytes: {magic.hex()}")

        model_id = header_data[2]
        version = header_data[3]

        gen_days = struct.unpack(">H", header_data[4:6])[0]
        start_days = struct.unpack(">H", header_data[6:8])[0]
        end_days = struct.unpack(">H", header_data[8:10])[0]

        # Parse user info (bytes 10-25)
        user_info = header_data[10:26]

        # Parse downloaded timestamp (bytes 26-33)
        downloaded_timestamp = struct.unpack(">Q", header_data[26:34])[0]

        # Calculate dates
        gen_base = datetime(2017, 9, 1)
        date_base = datetime(2024, 9, 1)

        header = {
            "model": model_id + 1,
            "version": version,
            "generation_date": gen_base + timedelta(days=gen_days),
            "start_date": date_base + timedelta(days=start_days),
            "end_date": date_base + timedelta(days=end_days),
            "user_info": user_info,
            "downloaded_timestamp": downloaded_timestamp,
        }

        return header, offset + 34

    def _parse_data(self):
        """Parse the complete bitmap data."""

        # Parse header
        self.header, offset = self._parse_header(self.data)
        self.model = self.header["model"]
        self.version = self.header["version"]
        self.start_date = self.header["start_date"]
        self.end_date = self.header["end_date"]

        self._log(f"Model: {self.model}, Version: {self.version}")
        self._log(f"Date range: {self.start_date} to {self.end_date}")

        # Create file-like object from remaining data
        remaining_data = self.data[offset:]
        f = io.BytesIO(remaining_data)

        # Parse based on model
        if self.model == 1:
            self._parse_model1(f)
        elif self.model == 2:
            self._parse_model2(f)
        elif self.model == 3:
            self._parse_model3(f)
        else:
            raise ValueError(f"Unsupported model: {self.model}")

    def _parse_model1(self, f: BinaryIO):
        """Parse Model 1 data (seen bitmap only)."""
        self._log("Parsing Model 1 bitmap")

        # Single bitmap for seen IPs
        self.bitmaps["seen"] = RoaringBitmapReader()
        self.bitmaps["seen"].read_from(f)

        self._log(f"Loaded seen bitmap with {self.bitmaps['seen'].num_containers} containers")

    def _parse_model2(self, f: BinaryIO):
        """Parse Model 2 data (5 bitmaps, possibly multi-date)."""
        if self.version == 2:
            # Multi-date format
            date_count = struct.unpack(">H", f.read(2))[0]
            self._log(f"Multi-date format with {date_count} dates")

            # Store bitmaps for each date
            for i in range(date_count):
                date_offset = struct.unpack(">H", f.read(2))[0]
                date = self.start_date.replace(year=2024, month=9, day=1) + timedelta(days=date_offset)
                date_str = date.strftime("%Y-%m-%d")
                self._log(f"Parsing data for date {date_str}")

                bitmap_names = [
                    "seen",
                    "benign",
                    "malicious",
                    "suspicious",
                    "3wh_completed",
                ]
                self.date_bitmaps[date_str] = {}

                for name in bitmap_names:
                    self._log(f"Parsing {name} bitmap")
                    bitmap = RoaringBitmapReader()
                    bitmap.read_from(f)
                    self.date_bitmaps[date_str][name] = bitmap
                    self._log(f"Loaded {name} bitmap with {bitmap.num_containers} containers")

                # Also store the last date's data in self.bitmaps for compatibility
                if i == date_count - 1:
                    self.bitmaps = self.date_bitmaps[date_str]
        else:
            # Single date format
            bitmap_names = [
                "seen",
                "benign",
                "malicious",
                "suspicious",
                "3wh_completed",
            ]

            for name in bitmap_names:
                self._log(f"Parsing {name} bitmap")
                self.bitmaps[name] = RoaringBitmapReader()
                self.bitmaps[name].read_from(f)
                self._log(f"Loaded {name} bitmap with \
                    {self.bitmaps[name].num_containers} containers")

    def _parse_model3(self, f: BinaryIO):
        """Parse Model 3 data (5 bitmaps + metadata)."""
        if self.version == 2:
            # Multi-date format with per-date metadata
            date_count = struct.unpack(">H", f.read(2))[0]
            self._log(f"Multi-date format with {date_count} dates")

            self.date_metadata = {}  # Store metadata for each date

            for i in range(date_count):
                date_offset = struct.unpack(">H", f.read(2))[0]
                date = self.start_date.replace(year=2024, month=9, day=1) + timedelta(days=date_offset)
                date_str = date.strftime("%Y-%m-%d")
                self._log(f"Parsing data for date {date_str}")

                # Parse bitmaps for this date
                bitmap_names = [
                    "seen",
                    "benign",
                    "malicious",
                    "suspicious",
                    "3wh_completed",
                ]
                self.date_bitmaps[date_str] = {}

                for name in bitmap_names:
                    self._log(f"Parsing {name} bitmap")
                    bitmap = RoaringBitmapReader()
                    bitmap.read_from(f)
                    self.date_bitmaps[date_str][name] = bitmap
                    self._log(f"Loaded {name} bitmap with {bitmap.num_containers} containers")

                # Parse metadata for this date
                self._log(f"Parsing metadata for date {date_str}")
                self.date_metadata[date_str] = self._parse_metadata(f)

                # Store the last date's data for compatibility
                if i == date_count - 1:
                    self.bitmaps = self.date_bitmaps[date_str]
                    self.metadata = self.date_metadata[date_str]
        else:
            # Single date format
            # First parse Model 2 bitmaps
            self._parse_model2(f)

            # Parse metadata
            self._log("Parsing Model 3 metadata")
            self.metadata = self._parse_metadata(f)

    def _parse_metadata(self, f: BinaryIO) -> Dict[str, Any]:
        """Parse Model 3 metadata from file."""
        metadata = {}

        # Actor list
        actor_count = struct.unpack(">H", f.read(2))[0]
        metadata["actors"] = []
        for i in range(actor_count):
            length = struct.unpack(">H", f.read(2))[0]
            actor = f.read(length).decode("utf-8")
            metadata["actors"].append(actor)
        self._log(f"Loaded {actor_count} actors")

        # Tag list
        tag_count = struct.unpack(">H", f.read(2))[0]
        metadata["tags"] = []
        for i in range(tag_count):
            length = struct.unpack(">H", f.read(2))[0]
            tag = f.read(length).decode("utf-8")
            metadata["tags"].append(tag)
        self._log(f"Loaded {tag_count} tags")

        # CVE list
        cve_count = struct.unpack(">H", f.read(2))[0]
        metadata["cves"] = []
        for i in range(cve_count):
            length = struct.unpack(">H", f.read(2))[0]
            cve = f.read(length).decode("utf-8")
            metadata["cves"].append(cve)
        self._log(f"Loaded {cve_count} CVEs")

        # IP mappings
        metadata["ip_actors"] = {}
        metadata["ip_tags"] = {}
        metadata["ip_cves"] = {}

        # Version 0 uses separate sections, version 2 uses combined format
        if self.version == 0:
            # Version 0 format: separate sections for IP-Actor, IP-Tag,
            # and IP-CVE mappings
            # Read IP->Actor mappings
            ip_actor_count = struct.unpack(">I", f.read(4))[0]
            self._log(f"Loading {ip_actor_count} IP-actor mappings")
            for i in range(ip_actor_count):
                ip_int = struct.unpack(">I", f.read(4))[0]
                actor_idx = struct.unpack(">H", f.read(2))[0]
                metadata["ip_actors"][ip_int] = actor_idx

            # Read IP->Tag mappings
            ip_tag_count = struct.unpack(">I", f.read(4))[0]
            self._log(f"Loading {ip_tag_count} IP-tag mappings")
            for i in range(ip_tag_count):
                ip_int = struct.unpack(">I", f.read(4))[0]
                tag_count = struct.unpack(">H", f.read(2))[0]
                tag_indices = []
                for _ in range(tag_count):
                    tag_indices.append(struct.unpack(">H", f.read(2))[0])
                metadata["ip_tags"][ip_int] = tag_indices

            # Read IP->CVE mappings
            ip_cve_count = struct.unpack(">I", f.read(4))[0]
            self._log(f"Loading {ip_cve_count} IP-CVE mappings")
            for i in range(ip_cve_count):
                ip_int = struct.unpack(">I", f.read(4))[0]
                cve_count = struct.unpack(">H", f.read(2))[0]
                cve_indices = []
                for _ in range(cve_count):
                    cve_indices.append(struct.unpack(">H", f.read(2))[0])
                metadata["ip_cves"][ip_int] = cve_indices
        else:
            # Version 2 format: combined mapping format
            mapping_count = struct.unpack(">I", f.read(4))[0]
            self._log(f"Loading {mapping_count} IP mappings")
            for i in range(mapping_count):
                try:
                    # Read IP
                    ip_data = f.read(4)
                    if len(ip_data) < 4:
                        self._log(f"ERROR: Insufficient data for IP at mapping {i}, \
                            expected 4 bytes, got {len(ip_data)}")
                        break
                    ip_int = struct.unpack(">I", ip_data)[0]

                    # Read actor index (0xFFFF means no actor)
                    actor_data = f.read(2)
                    if len(actor_data) < 2:
                        self._log(f"ERROR: Insufficient data for actor index at mapping {i}, \
                                expected 2 bytes, got {len(actor_data)}")
                        break
                    actor_idx = struct.unpack(">H", actor_data)[0]
                    if actor_idx != 0xFFFF and actor_idx < len(metadata["actors"]):
                        metadata["ip_actors"][ip_int] = actor_idx

                    # Read tag count and indices
                    tag_count_data = f.read(2)
                    if len(tag_count_data) < 2:
                        self._log(f"ERROR: Insufficient data for tag count at mapping {i}, \
                                expected 2 bytes, got {len(tag_count_data)}")
                        break
                    tag_count = struct.unpack(">H", tag_count_data)[0]
                    if tag_count > 0:
                        tag_indices = []
                        for j in range(tag_count):
                            tag_idx_data = f.read(2)
                            if len(tag_idx_data) < 2:
                                self._log(f"ERROR: Insufficient data for tag index {j} at \
                                        mapping {i}, expected 2 bytes, \
                                            got {len(tag_idx_data)}")
                                raise ValueError(f"Insufficient data for tag index {j} \
                                        at mapping {i}")
                            tag_idx = struct.unpack(">H", tag_idx_data)[0]
                            tag_indices.append(tag_idx)
                        metadata["ip_tags"][ip_int] = tag_indices

                    # Read CVE count and indices
                    cve_count_data = f.read(2)
                    if len(cve_count_data) < 2:
                        self._log(f"ERROR: Insufficient data for CVE count at mapping {i}, \
                                expected 2 bytes, got {len(cve_count_data)}")
                        break
                    cve_count = struct.unpack(">H", cve_count_data)[0]
                    if cve_count > 0:
                        cve_indices = []
                        for j in range(cve_count):
                            cve_idx_data = f.read(2)
                            if len(cve_idx_data) < 2:
                                self._log(f"ERROR: Insufficient data for CVE index {j} \
                                        at mapping {i}, expected 2 bytes, \
                                            got {len(cve_idx_data)}")
                                raise ValueError(f"Insufficient data for CVE index {j} \
                                        at mapping {i}")
                            cve_idx = struct.unpack(">H", cve_idx_data)[0]
                            cve_indices.append(cve_idx)
                        metadata["ip_cves"][ip_int] = cve_indices
                except Exception as e:
                    self._log(f"ERROR at mapping {i}: {e}")
                    raise

        return metadata

    def lookup_ip(self, ip_str: str) -> Dict[str, Any]:
        """Look up an IP address and return its data."""
        try:
            ip = ipaddress.IPv4Address(ip_str)
            ip_int = int(ip)
        except ValueError:
            raise ValueError(f"Invalid IP address: {ip_str}")

        # For multi-date format, check all dates
        if self.version == 2 and self.model == 3:
            results = []
            for date_str, bitmaps in self.date_bitmaps.items():
                if bitmaps["seen"].contains(ip_int):
                    result = {
                        "ip": ip_str,
                        "date": date_str,
                        "seen": True,
                        "3wh_completed": bitmaps["3wh_completed"].contains(ip_int),
                    }

                    # Determine classification
                    if bitmaps["benign"].contains(ip_int):
                        result["classification"] = "benign"
                    elif bitmaps["malicious"].contains(ip_int):
                        result["classification"] = "malicious"
                    elif bitmaps["suspicious"].contains(ip_int):
                        result["classification"] = "suspicious"
                    else:
                        result["classification"] = "unknown"

                    results.append(result)

            # Return the first match or a not-found result
            if results:
                return results[0]  # Return first occurrence
            else:
                return {
                    "ip": ip_str,
                    "date": self.header["start_date"].strftime("%Y-%m-%d"),
                    "seen": False,
                    "3wh_completed": False,
                    "classification": "unknown",
                }

        result = {"ip": ip_str, "date": self.header["start_date"].strftime("%Y-%m-%d")}

        if self.model == 1:
            result["seen"] = self.bitmaps["seen"].contains(ip_int)

        elif self.model == 2:
            # Model 2 data
            result["seen"] = self.bitmaps["seen"].contains(ip_int)
            result["3wh_completed"] = self.bitmaps["3wh_completed"].contains(ip_int)

            # Determine classification
            if self.bitmaps["benign"].contains(ip_int):
                result["classification"] = "benign"
            elif self.bitmaps["malicious"].contains(ip_int):
                result["classification"] = "malicious"
            elif self.bitmaps["suspicious"].contains(ip_int):
                result["classification"] = "suspicious"
            else:
                result["classification"] = "unknown"

        elif self.model == 3:
            # For Model 3, handle both single-date and multi-date formats
            if self.version == 2:
                # Multi-date format, check all dates
                results = []
                for date_str, bitmaps in self.date_bitmaps.items():
                    if bitmaps["seen"].contains(ip_int):
                        date_result = {
                            "ip": ip_str,
                            "date": date_str,
                            "seen": True,
                            "3wh_completed": bitmaps["3wh_completed"].contains(ip_int),
                        }

                        # Determine classification
                        if bitmaps["benign"].contains(ip_int):
                            date_result["classification"] = "benign"
                        elif bitmaps["malicious"].contains(ip_int):
                            date_result["classification"] = "malicious"
                        elif bitmaps["suspicious"].contains(ip_int):
                            date_result["classification"] = "suspicious"
                        else:
                            date_result["classification"] = "unknown"

                        # Add metadata for this date
                        metadata = self.date_metadata.get(date_str, {})
                        if ip_int in metadata.get("ip_actors", {}):
                            actor_idx = metadata["ip_actors"][ip_int]
                            date_result["actor"] = metadata["actors"][actor_idx]
                        else:
                            date_result["actor"] = "unknown"

                        if ip_int in metadata.get("ip_tags", {}):
                            tag_indices = metadata["ip_tags"][ip_int]
                            date_result["tags"] = [metadata["tags"][idx] for idx in tag_indices]
                        else:
                            date_result["tags"] = []

                        if ip_int in metadata.get("ip_cves", {}):
                            cve_indices = metadata["ip_cves"][ip_int]
                            date_result["cves"] = [metadata["cves"][idx] for idx in cve_indices]
                        else:
                            date_result["cves"] = []

                        results.append(date_result)

                # Return the first match or a not-found result
                if results:
                    return results[0]
                else:
                    return {
                        "ip": ip_str,
                        "date": self.header["start_date"].strftime("%Y-%m-%d"),
                        "seen": False,
                        "3wh_completed": False,
                        "classification": "unknown",
                        "actor": "unknown",
                        "tags": [],
                        "cves": [],
                    }
            else:
                # Single-date format
                result["seen"] = self.bitmaps["seen"].contains(ip_int)
                result["3wh_completed"] = self.bitmaps["3wh_completed"].contains(ip_int)

                # Determine classification
                if self.bitmaps["benign"].contains(ip_int):
                    result["classification"] = "benign"
                elif self.bitmaps["malicious"].contains(ip_int):
                    result["classification"] = "malicious"
                elif self.bitmaps["suspicious"].contains(ip_int):
                    result["classification"] = "suspicious"
                else:
                    result["classification"] = "unknown"

                # Add metadata
                if ip_int in self.metadata.get("ip_actors", {}):
                    actor_idx = self.metadata["ip_actors"][ip_int]
                    result["actor"] = self.metadata["actors"][actor_idx]
                else:
                    result["actor"] = "unknown"

                if ip_int in self.metadata.get("ip_tags", {}):
                    tag_indices = self.metadata["ip_tags"][ip_int]
                    result["tags"] = [self.metadata["tags"][idx] for idx in tag_indices]
                else:
                    result["tags"] = []

                if ip_int in self.metadata.get("ip_cves", {}):
                    cve_indices = self.metadata["ip_cves"][ip_int]
                    result["cves"] = [self.metadata["cves"][idx] for idx in cve_indices]
                else:
                    result["cves"] = []

        return result

    def get_stats(self) -> Dict[str, Any]:
        """Get statistics about the bitmap file."""
        stats = {
            "model": self.model,
            "version": self.header["version"],
            "generation_date": self.header["generation_date"].strftime("%Y-%m-%d"),
            "start_date": self.header["start_date"].strftime("%Y-%m-%d"),
            "end_date": self.header["end_date"].strftime("%Y-%m-%d"),
            "bitmaps": {},
        }

        # For multi-date format, aggregate stats across all dates
        if self.version == 2 and self.model in [2, 3]:
            all_ips = {}
            for bitmap_name in [
                "seen",
                "benign",
                "malicious",
                "suspicious",
                "3wh_completed",
            ]:
                all_ips[bitmap_name] = set()
                for date_str, bitmaps in self.date_bitmaps.items():
                    all_ips[bitmap_name].update(bitmaps[bitmap_name].get_all_values())
                stats["bitmaps"][bitmap_name] = len(all_ips[bitmap_name])
        else:
            # Count IPs in each bitmap
            for name, bitmap in self.bitmaps.items():
                count = len(bitmap.get_all_values())
                stats["bitmaps"][name] = count

        # Add metadata stats for Model 3
        if self.model == 3:
            if self.version == 2:
                # Aggregate metadata stats across all dates
                all_actors = set()
                all_tags = set()
                all_cves = set()
                all_ip_mappings = 0

                for date_str, metadata in self.date_metadata.items():
                    all_actors.update(metadata.get("actors", []))
                    all_tags.update(metadata.get("tags", []))
                    all_cves.update(metadata.get("cves", []))
                    all_ip_mappings += len(metadata.get("ip_actors", {}))

                stats["metadata"] = {
                    "actors": len(all_actors),
                    "tags": len(all_tags),
                    "cves": len(all_cves),
                    "ip_mappings": all_ip_mappings,
                }
            else:
                stats["metadata"] = {
                    "actors": len(self.metadata.get("actors", [])),
                    "tags": len(self.metadata.get("tags", [])),
                    "cves": len(self.metadata.get("cves", [])),
                    "ips_with_actors": len(self.metadata.get("ip_actors", {})),
                    "ips_with_tags": len(self.metadata.get("ip_tags", {})),
                    "ips_with_cves": len(self.metadata.get("ip_cves", {})),
                }

        return stats


class PsychicCache:
    """Cache manager for Psychic bitmaps."""

    def __init__(self, cache_dir: Optional[str] = None, max_age_hours: int = 1):
        """
        Initialize cache.

        :param cache_dir: Directory to store cached bitmaps (default: temp dir)
        :param max_age_hours: Maximum age of cached data in hours
        """
        if cache_dir is None:
            cache_dir = os.path.join(tempfile.gettempdir(), "greynoise_psychic")

        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.max_age_hours = max_age_hours

    def _get_cache_path(self, model: int, date: str) -> Path:
        """Get cache file path for a given model and date."""
        filename = f"psychic_m{model}_{date}.bin"
        return self.cache_dir / filename

    def _get_metadata_path(self, model: int, date: str) -> Path:
        """Get metadata file path for a given model and date."""
        filename = f"psychic_m{model}_{date}_metadata.json"
        return self.cache_dir / filename

    def is_cached(self, model: int, date: str) -> bool:
        """Check if bitmap is cached and not expired."""
        cache_path = self._get_cache_path(model, date)
        if not cache_path.exists():
            return False

        # Check if cache is expired
        cache_time = cache_path.stat().st_mtime
        current_time = time.time()
        age_hours = (current_time - cache_time) / 3600

        return age_hours < self.max_age_hours

    def get_cached(self, model: int, date: str) -> Optional[bytes]:
        """Get cached bitmap data."""
        if not self.is_cached(model, date):
            return None

        cache_path = self._get_cache_path(model, date)
        try:
            with open(cache_path, "rb") as f:
                return f.read()
        except Exception as e:
            logger.warning(f"Failed to read cached bitmap: {e}")
            return None

    def cache_bitmap(self, model: int, date: str, data: bytes) -> None:
        """Cache bitmap data."""
        cache_path = self._get_cache_path(model, date)
        try:
            with open(cache_path, "wb") as f:
                f.write(data)
            logger.debug(f"Cached bitmap to {cache_path}")
        except Exception as e:
            logger.warning(f"Failed to cache bitmap: {e}")

    def clear_expired(self) -> None:
        """Clear expired cache files."""
        current_time = time.time()
        for cache_file in self.cache_dir.glob("psychic_*.bin"):
            try:
                cache_time = cache_file.stat().st_mtime
                age_hours = (current_time - cache_time) / 3600
                if age_hours >= self.max_age_hours:
                    cache_file.unlink()
                    logger.debug(f"Removed expired cache file: {cache_file}")
            except Exception as e:
                logger.warning(f"Failed to remove expired cache file {cache_file}: {e}")


class Psychic:
    """
    High-performance offline IP lookup using Psychic bitmaps.

    This class provides fast IP lookups without API calls by using
    compressed bitmap data downloaded from GreyNoise.
    """

    PSYCHIC_BASE_URL = "https://api.greynoise.io/v1/psychic"

    def __init__(
        self,
        api_key: str,
        model: int = 1,
        cache_dir: Optional[str] = None,
        max_age_hours: int = 1,
        auto_download: bool = True,
    ):
        """
        Initialize Psychic bitmap client.

        :param api_key: GreyNoise API key
        :param model: Model to use (1, 2, or 3)
        :param cache_dir: Directory to cache bitmaps
        :param max_age_hours: Maximum age of cached data in hours
        :param auto_download: Automatically download bitmaps if not cached
        """
        if model not in [1, 2, 3]:
            raise ValueError("Model must be 1, 2, or 3")

        self.api_key = api_key
        self.model = model
        self.auto_download = auto_download
        self.cache = PsychicCache(cache_dir, max_age_hours)
        self.session = requests.Session()
        self.session.headers.update({"key": api_key, "User-Agent": PSYCHIC_USER_AGENT})

        self._parser = None
        self._last_loaded_date = None

        # Try to load current bitmap
        if auto_download:
            self._ensure_current_bitmap()

    def _get_today_date(self) -> str:
        """Get today's date in YYYY-MM-DD format."""
        return datetime.now().strftime("%Y-%m-%d")

    def _download_bitmap(self, date: str) -> bytes:
        """Download bitmap for a specific date."""
        url = self.PSYCHIC_BASE_URL
        payload = {"model": str(self.model), "date": date}

        logger.debug(f"Downloading bitmap from {url}")

        response = self.session.post(url, json=payload, timeout=300)  # 5 minute timeout for large files
        response.raise_for_status()

        if response.status_code == 200:
            return response.content
        else:
            raise Exception(f"Failed to download bitmap: HTTP {response.status_code}")

    def _download_mmdb(self, date: str) -> bytes:
        """Download mmdb for a specific date."""
        url = self.PSYCHIC_BASE_URL
        payload = {"model": str(self.model), "date": date, "format": "mmdb"}

        logger.debug(f"Downloading mmdb from {url}")

        response = self.session.post(url, json=payload, timeout=300)  # 5 minute timeout for large files
        response.raise_for_status()

        if response.status_code == 200:
            return response.content
        else:
            raise Exception(f"Failed to download mmdb: HTTP {response.status_code}")

    def download_mmdb(self, date: str, output_path: Optional[str] = None) -> str:
        """
        Download mmdb for a specific date and write it to disk.

        :param date: Date in YYYY-MM-DD format
        :param output_path: Directory to write the MMDB file (default: current directory)
        :return: Path to the written MMDB file
        """
        file_path = _psychic_output_path(
            output_path,
            Path("."),
            f"psychic_m{self.model}_{date}.mmdb",
        )

        logger.info(
            "Downloading MMDB for model %s, date %s, writing to %s",
            self.model,
            date,
            file_path,
        )
        mmdb_data = self._download_mmdb(date)
        file_path.write_bytes(mmdb_data)
        return str(file_path)

    def download_bitmap(self, date: str, output_path: Optional[str] = None) -> str:
        """
        Download bitmap for a specific date and write it to disk.

        :param date: Date in YYYY-MM-DD format
        :param output_path: Directory to write the bitmap file (default: current directory)
        :return: Path to the written bitmap file
        """
        file_path = _psychic_output_path(
            output_path,
            Path("."),
            f"psychic_m{self.model}_{date}.bin",
        )

        logger.info(
            "Downloading bitmap for model %s, date %s, writing to %s",
            self.model,
            date,
            file_path,
        )
        bitmap_data = self._download_bitmap(date)
        file_path.write_bytes(bitmap_data)
        return str(file_path)

    def download_csv(self, date: str, output_path: Optional[str] = None) -> str:
        """Download psychic MMDB data for a date and export it to CSV."""
        return self._download_csv(date, output_path)

    def _download_csv(self, date: str, output_path: Optional[str] = None) -> str:
        """
        Download psychic MMDB data for a date and export it to CSV.

        :param date: Date in YYYY-MM-DD format
        :param output_path: Directory or file path for the CSV (default: current directory)
        :return: Path to the written CSV file
        """
        file_path = _psychic_output_path(
            output_path,
            Path("."),
            f"psychic_m{self.model}_{date}.csv",
        )

        logger.info(
            "Downloading MMDB for model %s, date %s, exporting CSV to %s",
            self.model,
            date,
            file_path,
        )
        mmdb_data = self._download_mmdb(date)
        _write_mmdb_bytes_to_csv(mmdb_data, file_path, self.model)
        return str(file_path)

    def _generate_bitmap(self, start_date: str, end_date: str) -> bytes:
        """Generate bitmap for a date range."""
        url = self.PSYCHIC_BASE_URL
        payload = {
            "model": str(self.model),
            "start_date": start_date,
            "end_date": end_date,
        }

        logger.debug(f"Generating bitmap from {url}")

        response = self.session.post(url, json=payload, timeout=600)  # 10 minute timeout for generation
        response.raise_for_status()

        if response.status_code == 200:
            return response.content
        else:
            raise Exception(f"Failed to generate bitmap: HTTP {response.status_code}")

    def _ensure_current_bitmap(self) -> None:
        """Ensure we have current bitmap data loaded."""
        today = self._get_today_date()

        # Check if we already have current data loaded
        if self._parser and self._last_loaded_date == today:
            return

        # Clear expired cache
        self.cache.clear_expired()

        # Try to get from cache first
        cached_data = self.cache.get_cached(self.model, today)
        if cached_data:
            logger.debug(f"Loading cached bitmap for {today}")
            self._parser = PsychicBitmapParser(cached_data)
            self._last_loaded_date = today
            return

        # Download new bitmap
        try:
            logger.info(f"Downloading bitmap for model {self.model}, date {today}")
            data = self._download_bitmap(today)

            # Cache the data
            self.cache.cache_bitmap(self.model, today, data)

            # Parse the data
            self._parser = PsychicBitmapParser(data)
            self._last_loaded_date = today

            logger.info(f"Successfully loaded bitmap for {today}")

        except Exception as e:
            logger.error(f"Failed to download bitmap: {e}")
            raise

    def lookup_ip(self, ip: str) -> Dict[str, Any]:
        """
        Look up an IP address in the bitmap.

        :param ip: IP address to look up
        :return: Dictionary with IP information
        """
        if not self._parser:
            if self.auto_download:
                self._ensure_current_bitmap()
            else:
                raise RuntimeError("No bitmap loaded. Set auto_download=True or call load_bitmap()")

        return self._parser.lookup_ip(ip)

    def lookup_ips(self, ips: List[str]) -> List[Dict[str, Any]]:
        """
        Look up multiple IP addresses in the bitmap.

        :param ips: List of IP addresses to look up
        :return: List of dictionaries with IP information
        """
        return [self.lookup_ip(ip) for ip in ips]

    def get_stats(self) -> Dict[str, Any]:
        """Get statistics about the loaded bitmap."""
        if not self._parser:
            if self.auto_download:
                self._ensure_current_bitmap()
            else:
                raise RuntimeError("No bitmap loaded. Set auto_download=True or call load_bitmap()")

        return self._parser.get_stats()

    def load_bitmap(self, date: Optional[str] = None) -> None:
        """
        Manually load bitmap for a specific date.

        :param date: Date in YYYY-MM-DD format (default: today)
        """
        if date is None:
            date = self._get_today_date()

        # Check cache first
        cached_data = self.cache.get_cached(self.model, date)
        if cached_data:
            logger.debug(f"Loading cached bitmap for {date}")
            self._parser = PsychicBitmapParser(cached_data)
            self._last_loaded_date = date
            return

        # Download bitmap
        try:
            logger.info(f"Downloading bitmap for model {self.model}, date {date}")
            data = self._download_bitmap(date)

            # Cache the data
            self.cache.cache_bitmap(self.model, date, data)

            # Parse the data
            self._parser = PsychicBitmapParser(data)
            self._last_loaded_date = date

            logger.info(f"Successfully loaded bitmap for {date}")

        except Exception as e:
            logger.error(f"Failed to download bitmap for {date}: {e}")
            raise

    def reload(self) -> None:
        """Force reload of current bitmap data."""
        date = self._last_loaded_date or self._get_today_date()

        # Remove from cache to force fresh download
        cache_path = self.cache._get_cache_path(self.model, date)
        if cache_path.exists():
            cache_path.unlink()

        self.load_bitmap(date)

    def is_loaded(self) -> bool:
        """Check if a bitmap is currently loaded."""
        return self._parser is not None
