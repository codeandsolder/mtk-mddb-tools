"""Read-only search helpers for reconstructed MediaTek MDDB RocksDB databases."""

from __future__ import annotations

import os
import shutil
import tempfile
from collections.abc import Generator, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

from rocksdict import AccessType, Options, Rdict

from .edb import extract


@dataclass(frozen=True)
class Match:
    """One textual match in a raw RocksDB key or value."""

    column_family: str
    field: str
    key: bytes
    offset: int
    blob: bytes


def _raw_options() -> Options:
    options = Options(raw_mode=True)
    options.create_if_missing(False)
    return options


def _link_or_copy(src: Path, dst: Path) -> None:
    dst.parent.mkdir(parents=True, exist_ok=True)
    try:
        os.link(src, dst)
    except OSError:
        shutil.copy2(src, dst)


@contextmanager
def rocksdb_view(source: Path) -> Generator[Path, None, None]:
    """Yield a RocksDB-openable view of an EDB or extracted database.

    MediaTek packages some SSTs beneath ``sp/`` even though the embedded
    manifest references their basenames. A temporary flattened view keeps the
    faithful extraction intact while making stock RocksDB readers happy.
    """
    if source.is_file():
        with tempfile.TemporaryDirectory(prefix="mtk-mddb-extract-") as temp_dir:
            extracted = Path(temp_dir)
            extract(source, extracted)
            with rocksdb_view(extracted / "rocksdb") as view:
                yield view
        return

    rocksdb_dir = source / "rocksdb" if (source / "rocksdb").is_dir() else source
    if not (rocksdb_dir / "CURRENT").is_file():
        raise ValueError(f"{rocksdb_dir} does not look like an extracted RocksDB")

    sp_dir = rocksdb_dir / "sp"
    sp_files = sorted(sp_dir.glob("*.sst")) if sp_dir.is_dir() else []
    if not sp_files:
        yield rocksdb_dir
        return

    with tempfile.TemporaryDirectory(prefix="mtk-mddb-rocks-") as temp_dir:
        view = Path(temp_dir)
        for entry in rocksdb_dir.iterdir():
            if entry.is_file():
                _link_or_copy(entry, view / entry.name)
        for entry in sp_files:
            target = view / entry.name
            if not target.exists():
                _link_or_copy(entry, target)
        yield view


@contextmanager
def open_raw_db(path: Path) -> Generator[tuple[Rdict, list[str]], None, None]:
    """Open every column family in raw-byte, read-only mode."""
    names = Rdict.list_cf(str(path))
    main_options = _raw_options()
    column_families = {name: _raw_options() for name in names if name != "default"}
    db = Rdict(str(path), main_options, column_families, AccessType.read_only())
    try:
        yield db, names
    finally:
        db.close()


def render(data: bytes, start: int, end: int) -> str:
    """Render binary context with printable ASCII and escaped control bytes."""
    out: list[str] = []
    for value in data[start:end]:
        if 32 <= value < 127:
            out.append(chr(value))
        elif value == 0:
            out.append(r"\0")
        elif value == 10:
            out.append(r"\n")
        elif value == 13:
            out.append(r"\r")
        elif value == 9:
            out.append(r"\t")
        else:
            out.append(f"\\x{value:02x}")
    return "".join(out)


def search_blob(data: bytes, needle: bytes) -> Iterator[int]:
    """Yield all overlapping occurrences of ``needle`` in ``data``."""
    pos = 0
    while True:
        hit = data.find(needle, pos)
        if hit < 0:
            return
        yield hit
        pos = hit + 1


def iter_matches(
    db: Rdict,
    names: list[str],
    needle: bytes,
    *,
    column_families: list[str] | None = None,
) -> Iterator[Match]:
    """Search raw keys and values across selected column families."""
    selected = column_families or names
    unknown = sorted(set(selected) - set(names))
    if unknown:
        msg = "unknown column families: " + ", ".join(unknown)
        raise ValueError(msg)

    for cf_name in selected:
        cf = db if cf_name == "default" else db.get_column_family(cf_name)
        for key, value in cf.items():
            if not isinstance(key, bytes) or not isinstance(value, bytes):
                raise TypeError("raw-mode RocksDB returned a non-bytes key/value")
            for field_name, blob in (("key", key), ("value", value)):
                for offset in search_blob(blob, needle):
                    yield Match(cf_name, field_name, key, offset, blob)
