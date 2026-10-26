"""Decode the CATD container used by MediaTek Catcher/META MDDB .EDB files."""

from __future__ import annotations

import hashlib
import itertools
import json
import lzma
import struct
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import TypedDict


class EdbError(ValueError):
    """Raised when an EDB file is malformed or uses an unsupported layout."""


@dataclass(frozen=True)
class Section:
    """One compressed CATD section."""

    name: str
    offset: int
    compressed_size: int
    uncompressed_size: int


@dataclass(frozen=True)
class PackedFile:
    """One file recovered from decompressed DATAI."""

    name: str
    payload: bytes


class SectionManifest(TypedDict):
    """Manifest entry for a decoded CATD section."""

    name: str
    offset: int
    compressed_size: int
    uncompressed_size: int
    sha256: str


class FileManifest(TypedDict):
    """Manifest entry for a reconstructed RocksDB file."""

    name: str
    size: int
    sha256: str


class Manifest(TypedDict):
    """Machine-readable extraction summary."""

    input: str
    input_size: int
    input_sha256: str
    sections: list[SectionManifest]
    rocksdb_files: list[FileManifest]
    dataa_size: int
    dataa_sha256: str


def _u32(data: bytes, offset: int) -> int:
    return struct.unpack_from("<I", data, offset)[0]


def _u64(data: bytes, offset: int) -> int:
    return struct.unpack_from("<Q", data, offset)[0]


def parse_sections(blob: bytes) -> list[Section]:
    """Locate DATAI and DATAA descriptors in a CATD EDB container."""
    if not blob.startswith(b"CATD"):
        raise EdbError("not a CATD EDB file")

    sections: list[Section] = []
    for name in ("DATAI", "DATAA"):
        tag = name.encode("ascii") + b"\0\0\0"
        at = blob.find(tag, 0, min(len(blob), 4096))
        if at < 0 or at + 20 > len(blob):
            raise EdbError(f"missing {name} descriptor")

        offset = _u32(blob, at + 8)
        compressed_size = _u32(blob, at + 12)
        uncompressed_size = _u32(blob, at + 16)
        end = offset + compressed_size
        if compressed_size <= 5 or end > len(blob):
            raise EdbError(f"invalid {name} bounds: {offset:#x}+{compressed_size:#x}")

        sections.append(Section(name, offset, compressed_size, uncompressed_size))

    ordered = sorted(sections, key=lambda section: section.offset)
    for left, right in itertools.pairwise(ordered):
        if left.offset + left.compressed_size > right.offset:
            raise EdbError(f"overlapping sections: {left.name}, {right.name}")
    return sections


def decompress_section(blob: bytes, section: Section) -> bytes:
    """Decode MediaTek's five-byte LZMA1 header plus raw LZMA stream."""
    payload = blob[section.offset : section.offset + section.compressed_size]
    if len(payload) < 5:
        raise EdbError(f"{section.name}: truncated LZMA header")

    prop = payload[0]
    if prop >= 9 * 5 * 5:
        raise EdbError(f"{section.name}: invalid LZMA property byte {prop:#x}")

    lc = prop % 9
    rest = prop // 9
    lp = rest % 5
    pb = rest // 5
    dict_size = _u32(payload, 1)
    filters = [
        {
            "id": lzma.FILTER_LZMA1,
            "dict_size": dict_size,
            "lc": lc,
            "lp": lp,
            "pb": pb,
        }
    ]
    try:
        out = lzma.decompress(payload[5:], format=lzma.FORMAT_RAW, filters=filters)
    except lzma.LZMAError as exc:
        raise EdbError(f"{section.name}: raw LZMA decode failed: {exc}") from exc

    if len(out) != section.uncompressed_size:
        raise EdbError(
            f"{section.name}: decoded {len(out)} bytes, expected {section.uncompressed_size}"
        )
    return out


def parse_datai_archive(data: bytes) -> list[PackedFile]:
    """Recover the packed RocksDB directory from decompressed DATAI.

    Each record begins with a little-endian u64 span. The span is measured from
    the following filename start to the following record's filename start. The
    filename is NUL-terminated; the payload occupies the bytes after it through
    eight bytes before the next filename. The final record uses the same rule,
    with its virtual next filename eight bytes beyond EOF.
    """
    files: list[PackedFile] = []
    pos = 0
    seen: set[str] = set()

    while pos < len(data):
        if pos + 8 > len(data):
            raise EdbError(f"DATAI: truncated record header at {pos:#x}")

        span = _u64(data, pos)
        name_start = pos + 8
        name_end = data.find(b"\0", name_start, min(len(data), name_start + 4096))
        if name_end < 0:
            raise EdbError(f"DATAI: unterminated filename at {name_start:#x}")

        try:
            name = data[name_start:name_end].decode("utf-8")
        except UnicodeDecodeError as exc:
            raise EdbError(f"DATAI: non-UTF-8 filename at {name_start:#x}") from exc

        path = PurePosixPath(name)
        if not name or path.is_absolute() or ".." in path.parts:
            raise EdbError(f"DATAI: unsafe filename {name!r}")
        if name in seen:
            raise EdbError(f"DATAI: duplicate filename {name!r}")
        seen.add(name)

        next_name_start = name_start + span
        payload_start = name_end + 1
        payload_end = next_name_start - 8
        if span < (name_end - name_start + 1) + 8:
            raise EdbError(f"DATAI: impossible span {span:#x} for {name!r}")
        if payload_end < payload_start or payload_end > len(data):
            raise EdbError(f"DATAI: invalid payload bounds for {name!r}")

        files.append(PackedFile(name, data[payload_start:payload_end]))
        pos = payload_end

    if pos != len(data):
        raise EdbError(f"DATAI: archive ended at {pos:#x}, expected {len(data):#x}")
    return files


def sha256(data: bytes) -> str:
    """Return a lowercase SHA-256 digest."""
    return hashlib.sha256(data).hexdigest()


def extract(input_path: Path, output_dir: Path, *, keep_datai: bool = False) -> Manifest:
    """Extract one EDB into RocksDB files, DATAA, and a JSON manifest."""
    blob = input_path.read_bytes()
    sections = parse_sections(blob)
    decoded = {section.name: decompress_section(blob, section) for section in sections}
    files = parse_datai_archive(decoded["DATAI"])

    output_dir.mkdir(parents=True, exist_ok=True)
    rocksdb_dir = output_dir / "rocksdb"
    rocksdb_dir.mkdir(parents=True, exist_ok=True)

    file_manifest: list[FileManifest] = []
    for item in files:
        out = rocksdb_dir.joinpath(*PurePosixPath(item.name).parts)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_bytes(item.payload)
        file_manifest.append(
            {
                "name": item.name,
                "size": len(item.payload),
                "sha256": sha256(item.payload),
            }
        )

    dataa = decoded["DATAA"]
    (output_dir / "DATAA.bin").write_bytes(dataa)
    if keep_datai:
        (output_dir / "DATAI.bin").write_bytes(decoded["DATAI"])

    section_manifest: list[SectionManifest] = [
        {
            "name": section.name,
            "offset": section.offset,
            "compressed_size": section.compressed_size,
            "uncompressed_size": section.uncompressed_size,
            "sha256": sha256(decoded[section.name]),
        }
        for section in sections
    ]
    manifest: Manifest = {
        "input": str(input_path),
        "input_size": len(blob),
        "input_sha256": sha256(blob),
        "sections": section_manifest,
        "rocksdb_files": file_manifest,
        "dataa_size": len(dataa),
        "dataa_sha256": sha256(dataa),
    }
    (output_dir / "manifest.json").write_text(
        json.dumps(manifest, indent=2) + "\n",
        encoding="utf-8",
    )
    return manifest
