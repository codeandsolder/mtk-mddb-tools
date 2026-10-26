"""Console entry points for mtk-mddb-tools."""

from __future__ import annotations

import argparse
from pathlib import Path

from .edb import extract
from .query import iter_matches, open_raw_db, render, rocksdb_view


def extract_main() -> int:
    """Run the EDB extractor CLI."""
    parser = argparse.ArgumentParser(description="Extract a MediaTek CATD/MDDB .EDB database")
    parser.add_argument("edb", type=Path)
    parser.add_argument("-o", "--output", type=Path, required=True)
    parser.add_argument(
        "--keep-datai",
        action="store_true",
        help="also save the full decompressed DATAI blob",
    )
    args = parser.parse_args()

    manifest = extract(args.edb, args.output, keep_datai=args.keep_datai)
    rocksdb_path = args.output / "rocksdb"
    print(f"extracted {len(manifest['rocksdb_files'])} RocksDB files to {rocksdb_path}")
    for section in manifest["sections"]:
        print(
            f"{section['name']}: {section['compressed_size']} -> "
            f"{section['uncompressed_size']} bytes"
        )
    print(f"DATAA: {manifest['dataa_size']} bytes -> {args.output / 'DATAA.bin'}")
    return 0


def query_main() -> int:
    """Run the raw RocksDB search CLI."""
    parser = argparse.ArgumentParser(
        description="Search a MediaTek MDDB .EDB or an extracted RocksDB"
    )
    parser.add_argument("source", type=Path, help=".EDB file or extracted RocksDB directory")
    parser.add_argument("needle", help="UTF-8 text to search for")
    parser.add_argument(
        "--cf",
        action="append",
        dest="column_families",
        help="restrict to a column family; repeatable",
    )
    parser.add_argument("--limit", type=int, default=50, help="maximum matches to print")
    parser.add_argument(
        "--context",
        type=int,
        default=96,
        help="bytes of context on each side",
    )
    args = parser.parse_args()

    if args.limit <= 0 or args.context < 0:
        parser.error("--limit must be positive and --context non-negative")

    needle = args.needle.encode()
    printed = 0
    records_scanned = 0

    with rocksdb_view(args.source) as view, open_raw_db(view) as (db, names):
        try:
            matches = iter_matches(
                db,
                names,
                needle,
                column_families=args.column_families,
            )
            for match in matches:
                records_scanned += 1
                lo = max(0, match.offset - args.context)
                hi = min(len(match.blob), match.offset + len(needle) + args.context)
                print(
                    f"cf={match.column_family} field={match.field} key={match.key.hex()} "
                    f"offset={match.offset:#x} len={len(match.blob)}"
                )
                print(render(match.blob, lo, hi))
                print()
                printed += 1
                if printed >= args.limit:
                    print(f"matches_shown={printed} (limit reached)")
                    return 0
        except ValueError as exc:
            parser.error(str(exc))

    print(f"matches_shown={printed} records_with_matches={records_scanned}")
    return 0
