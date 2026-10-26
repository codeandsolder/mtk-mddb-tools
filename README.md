# mtk-mddb-tools

Small tools for unpacking and searching MediaTek Catcher/META modem database (`MDDB_*.EDB`) files.

This started while reverse-engineering a Fibocom FM350-GL / MediaTek T700 modem. The production firmware ships a roughly 10 MB `MDDB_InfoCustomAppSrcP_MT6880_*.EDB`; the outer format turned out to be pleasantly mundane:

```text
CATD
├── DATAI  -- raw LZMA1 --> packed RocksDB directory
└── DATAA  -- raw LZMA1 --> companion binary metadata
```

`DATAI` reconstructs an ordinary RocksDB with column families such as `trace`, `type`, `struct`, `enum`, `message`, `file`, `l1module`, `l1filter`, `nvram`, and the `sp` string pool. On the tested MT6880 database this exposes useful factory/debug vocabulary including `INJ_EL1D_RX_IQ_DUMP`, `URF_TEST_CMD_TRIGGER_IQ_DUMP_MODE_V3`, and `URF_TEST_CMD_GET_IQ_DUMP_RESULT_V3`.

No modem firmware or extracted vendor database content is included in this repository.

## Install / run

With `uv`:

```bash
uv sync
```

Extract an EDB:

```bash
uv run mtk-mddb-extract MDDB_InfoCustomAppSrcP_MT6880_....EDB -o out
```

The output contains:

```text
out/
├── DATAA.bin
├── manifest.json
└── rocksdb/
    ├── CURRENT
    ├── MANIFEST-...
    ├── OPTIONS-...
    ├── *.sst
    └── sp/*.sst
```

Search the embedded database directly without keeping an extraction:

```bash
uv run mtk-mddb-query MDDB_InfoCustomAppSrcP_MT6880_....EDB IQ_DUMP
```

Restrict a search to one or more column families:

```bash
uv run mtk-mddb-query modem.EDB URF_TEST_CMD --cf sp --limit 20
```

You can also point `mtk-mddb-query` at an already-extracted `rocksdb/` directory.

## What is decoded

The tool currently understands:

- the `CATD` header well enough to locate and validate `DATAI` / `DATAA`;
- MediaTek's five-byte LZMA1 properties/dictionary prefix followed by a raw LZMA stream;
- the packed-file chain inside `DATAI`;
- reconstruction of the embedded RocksDB directory;
- read-only raw searching across all RocksDB column families.

The extractor rejects path traversal, duplicate archive names, invalid section bounds, inconsistent decompressed sizes, and malformed LZMA properties.

## What is *not* decoded yet

The RocksDB values are a richer schema, not just strings. Records in `type`, `struct`, `enum`, `trace`, and related column families contain references to other records/tables. The query command deliberately exposes raw bytes plus readable context while that logical schema is being mapped.

In particular, this repository does **not** yet turn an enum name such as `URF_TEST_CMD_TRIGGER_IQ_DUMP_MODE_V3` directly into its numeric command ID and request/result structure. That's the obvious next layer.

## Compatibility

Tested against a production Fibocom FM350-GL / MediaTek MT6880 database from firmware family `81600.0000.00.29.23.x` (Python 3.11+). Other MediaTek Catcher/META generations may use related but different containers; unsupported layouts should fail loudly rather than being guessed at.

One packaging quirk in the tested file places several SSTs under `sp/` while the RocksDB manifest refers to their basenames. `mtk-mddb-query` creates a temporary hard-linked/copy compatibility view for those files and opens that view read-only; the faithful extracted directory is left untouched.

## Development

```bash
uv sync --all-groups
uv run ruff check .
uv run ruff format --check .
uv run ty check
uv run pytest
```
