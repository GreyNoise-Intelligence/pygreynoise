"""Portable Roaring bitmap decoding and Psychic file alignment."""

import io
import struct

import pytest

from greynoise.psychic import PsychicBitmapParser, RoaringBitmapReader


@pytest.mark.parametrize(
    "data, expected",
    [
        (bytes.fromhex("3a300000 00000000"), set()),
        (
            bytes.fromhex("3a300000 01000000 01000100 10000000 01000300"),
            {65537, 65539},
        ),
        (
            bytes.fromhex("3b300000 01 01000200 010005000200"),
            {65541, 65542, 65543},
        ),
        (
            bytes.fromhex("3b300000 01 07000500 0200000001000a000300"),
            {458752, 458753, 458762, 458763, 458764, 458765},
        ),
        (
            bytes.fromhex("3b300000 00 01000100 01000300"),
            {65537, 65539},
        ),
        (
            bytes.fromhex("3b300200 02 01000000 02000200 03000000 0900 010005000200 0a00"),
            {65545, 131077, 131078, 131079, 196618},
        ),
        (
            bytes.fromhex("3b300300 09 01000200 02000100 03000010 0400ffff")
            + struct.pack("<4I", 37, 43, 47, 8239)
            + bytes.fromhex("010005000200 02000900")
            + b"\xff" * 512
            + b"\x01"
            + bytes(7679)
            + bytes.fromhex("01000000ffff"),
            {65541, 65542, 65543, 131074, 131081} | set(range(196608, 200705)) | set(range(262144, 327680)),
        ),
        (
            bytes.fromhex("3b300800 0001")
            + b"".join(struct.pack("<HH", key, 0) for key in range(8))
            + bytes.fromhex("08000200")
            + struct.pack("<9I", 78, 80, 82, 84, 86, 88, 90, 92, 94)
            + bytes.fromhex("0100") * 8
            + bytes.fromhex("010005000200"),
            {1, 65537, 131073, 196609, 262145, 327681, 393217, 458753, 524293, 524294, 524295},
        ),
    ],
    ids=[
        "empty",
        "no-run-with-offset",
        "run-without-offset",
        "multiple-runs",
        "run-layout-array",
        "three-containers",
        "mixed",
        "nine-containers",
    ],
)
def test_roaring_reader_preserves_values_and_stream_position(data, expected):
    """Both layouts decode their values without consuming the following section."""
    stream = io.BytesIO(data + b"next-section")
    reader = RoaringBitmapReader()

    reader.read_from(stream)

    assert reader.get_all_values() == expected
    assert stream.read() == b"next-section"


@pytest.mark.parametrize(
    "data, message",
    [
        (bytes.fromhex("3b300000"), "run flags"),
        (bytes.fromhex("3b300000 01 01000200"), "run count"),
        (bytes.fromhex("3b300000 01 01000200 01000500"), "run container"),
        (bytes.fromhex("3b300000 01 01000200 0100ffff0200"), "Invalid run"),
        (bytes.fromhex("3b300000 01 01000200 010005000100"), "cardinality"),
        (bytes.fromhex("3b300000 01 01000300 02000500010006000100"), "Invalid run"),
    ],
    ids=["missing-flags", "missing-count", "truncated-run", "overflow", "wrong-cardinality", "overlap"],
)
def test_roaring_reader_rejects_malformed_runs(data, message):
    """Malformed run data fails explicitly instead of shifting subsequent sections."""
    with pytest.raises(ValueError, match=message):
        RoaringBitmapReader().read_from(io.BytesIO(data))


@pytest.mark.parametrize("model", [1, 2, 3])
def test_psychic_parser_reads_run_bitmap_before_other_sections(model):
    """Run compression preserves the remaining bitmaps and Model 3 metadata."""
    header = b"GN" + bytes([model - 1, 0]) + bytes(30)
    seen = bytes.fromhex("3b300000 01 01000200 010005000200")
    empty_bitmap = bytes.fromhex("3a300000 00000000")
    body = seen
    if model > 1:
        body += empty_bitmap * 4
    if model == 3:
        body += (
            bytes.fromhex("0001 0007")
            + b"Scanner"
            + bytes.fromhex("0001 0003")
            + b"Tag"
            + bytes.fromhex("0001 000a")
            + b"CVE-2026-1"
            + bytes.fromhex("00000001 00010005 0000")
            + bytes.fromhex("00000001 00010005 0001 0000")
            + bytes.fromhex("00000001 00010005 0001 0000")
        )

    parser = PsychicBitmapParser(header + body)

    assert parser.bitmaps["seen"].get_all_values() == {65541, 65542, 65543}
    if model > 1:
        assert parser.bitmaps["3wh_completed"].get_all_values() == set()
    if model == 3:
        assert parser.metadata == {
            "actors": ["Scanner"],
            "tags": ["Tag"],
            "cves": ["CVE-2026-1"],
            "ip_actors": {65541: 0},
            "ip_tags": {65541: [0]},
            "ip_cves": {65541: [0]},
        }
