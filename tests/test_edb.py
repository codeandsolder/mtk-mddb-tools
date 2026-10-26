"""Synthetic tests for the CATD/LZMA and DATAI container layers."""

from __future__ import annotations

import lzma
import struct
from pathlib import Path

import pytest

from mtk_mddb.edb import EdbError, extract, parse_datai_archive, parse_sections


def _pack_datai(files: list[tuple[str, bytes]]) -> bytes:
    chunks: list[bytes] = []
    for name, payload in files:
        encoded = name.encode()
        span = len(encoded) + 1 + len(payload) + 8
        chunks.append(struct.pack("<Q", span) + encoded + b"\0" + payload)
    return b"".join(chunks)


def _raw_lzma(data: bytes) -> bytes:
    lc, lp, pb = 3, 0, 2
    prop = (pb * 5 + lp) * 9 + lc
    dict_size = 1 << 20
    filters = [
        {
            "id": lzma.FILTER_LZMA1,
            "dict_size": dict_size,
            "lc": lc,
            "lp": lp,
            "pb": pb,
        }
    ]
    compressed = lzma.compress(data, format=lzma.FORMAT_RAW, filters=filters)
    return bytes([prop]) + struct.pack("<I", dict_size) + compressed


def _build_edb(datai: bytes, dataa: bytes) -> bytes:
    compressed_i = _raw_lzma(datai)
    compressed_a = _raw_lzma(dataa)
    header = bytearray(94)
    header[:4] = b"CATD"
    datai_offset = len(header)
    dataa_offset = datai_offset + len(compressed_i)

    def descriptor(at: int, name: bytes, offset: int, compressed: bytes, raw: bytes) -> None:
        header[at : at + 8] = name + b"\0" * (8 - len(name))
        struct.pack_into("<III", header, at + 8, offset, len(compressed), len(raw))

    descriptor(48, b"DATAI", datai_offset, compressed_i, datai)
    descriptor(74, b"DATAA", dataa_offset, compressed_a, dataa)
    return bytes(header) + compressed_i + compressed_a


def test_parse_datai_archive_round_trip() -> None:
    raw = _pack_datai([("CURRENT", b"MANIFEST-000001\n"), ("sp/000007.sst", b"sst")])
    files = parse_datai_archive(raw)
    assert [(item.name, item.payload) for item in files] == [
        ("CURRENT", b"MANIFEST-000001\n"),
        ("sp/000007.sst", b"sst"),
    ]


def test_rejects_path_traversal() -> None:
    raw = _pack_datai([("../nope", b"x")])
    with pytest.raises(EdbError, match="unsafe filename"):
        parse_datai_archive(raw)


def test_extract_synthetic_edb(tmp_path: Path) -> None:
    datai = _pack_datai([("CURRENT", b"MANIFEST-000001\n"), ("000007.sst", b"sst-data")])
    dataa = b"TRACE_ERROR\0synthetic\0"
    edb = _build_edb(datai, dataa)
    source = tmp_path / "test.EDB"
    output = tmp_path / "out"
    source.write_bytes(edb)

    sections = parse_sections(edb)
    assert [section.name for section in sections] == ["DATAI", "DATAA"]

    manifest = extract(source, output, keep_datai=True)
    assert (output / "rocksdb" / "CURRENT").read_bytes() == b"MANIFEST-000001\n"
    assert (output / "rocksdb" / "000007.sst").read_bytes() == b"sst-data"
    assert (output / "DATAA.bin").read_bytes() == dataa
    assert (output / "DATAI.bin").read_bytes() == datai
    assert len(manifest["rocksdb_files"]) == 2
