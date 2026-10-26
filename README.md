# mtk-mddb-tools

Ghidra extension and command-line tools for MediaTek Catcher/META modem databases (`MDDB_*.EDB`).

This started while reverse-engineering a Fibocom FM350-GL / MediaTek T700 modem. The shipping firmware contains a roughly 10 MB `MDDB_InfoCustomAppSrcP_MT6880_*.EDB`; it turns out to be a small `CATD` container around a perfectly ordinary RocksDB:

```text
CATD
├── DATAI  -- raw LZMA1 --> packed RocksDB directory
└── DATAA  -- raw LZMA1 --> companion trace/category metadata
```

On the tested MT6880 database, `DATAI` reconstructs 18 RocksDB column families including `sp`, `trace`, `type`, `struct`, `enum`, `message`, `file`, `l1module`, `l1filter`, and `nvram`.

The Ghidra plugin is the main interface. It opens an EDB directly, searches the database, decodes the common packed string-reference and enum representation, maps names back into the current program, follows Ghidra xrefs into code, and can annotate those matches.

No modem firmware or extracted vendor database content is included in this repository.

## Ghidra extension

### Install

Download the release zip matching the machine running Ghidra:

- `linux64`
- `win64`
- `osx` (contains both x86-64 and arm64 RocksDB natives)

In Ghidra 12.2:

1. **File → Install Extensions...**
2. Add/select the downloaded `mtk-mddb-tools-ghidra-12.2-*.zip`.
3. Restart Ghidra.
4. If necessary, enable **MediaTek MDDB** in **File → Configure...**.
5. Use **Tools → MediaTek MDDB → Open EDB...** from CodeBrowser.

### What the plugin does

The dockable **MediaTek MDDB** browser provides:

- direct opening of `CATD` `.EDB` files or previously extracted RocksDB directories;
- read-only search across all column families or one selected family;
- readable context around binary RocksDB values;
- MediaTek packed string-pool reference decoding (`14-bit bucket + 18-bit byte offset`);
- decoding of the standard MDDB enum record layout;
- enum/type-name backreferences where the database exposes them;
- **Find in Program** for exact firmware string matches;
- **Go to Code Xref** to jump from a matched firmware string to code using Ghidra's reference database;
- **Annotate Program** to add analysis labels, comments, and bookmarks at strings and code xrefs.

For example, the tested FM350/T700 MDDB decodes:

```text
urf_test_cmd_type = 0x58  URF_TEST_CMD_TRIGGER_IQ_DUMP_MODE_V3
urf_test_cmd_type = 0x59  URF_TEST_CMD_GET_IQ_DUMP_RESULT_V3
urf_test_cmd_type = 0x28  URF_TEST_CMD_SET_RX_ANTENNA
```

The same database exposes the corresponding request/confirmation vocabulary, including:

```text
UTSTReqTriggerIqDumpModeV3lp       trigger_iq_dump_v3_lp
UTSTCnfTriggerIqDumpModeV3lp       cnf_trigger_iq_dump_v3_lp
UTSTCnfGetIqDumpResultV3lp         cnf_get_iq_data_v3_lp
u_trigger_iq_dump_mode_v3_req_param_struct
u_trigger_iq_dump_mode_v3_cnf_param_struct
u_get_iq_dump_result_v3_req_param_struct
u_get_iq_dump_result_v3_cnf_param_struct
```

The last `u_*_param_struct` names are present in the string pool but are not directly joined to the dispatch types by the packed-reference mechanism used for enums and union members. The plugin deliberately leaves that final generation-specific PDU-schema join unresolved rather than guessing it.

### Program integration tested on FM350

Against a fully analyzed nanoMIPS FM350 image, the plugin's bridge from MDDB/debug vocabulary to Ghidra code was exercised end-to-end. For example:

- `dhl_inject_string`: 3 MDDB hits, 4 firmware string occurrences, 1 code xref at `0x9021cb94`;
- `NL1_RXDFE_TRIGGER_IQ_DUMP`: 2 firmware occurrences and a code xref at `0x90dc52b2`.

The latter string is present in the firmware rather than this particular MDDB build, which is why the database and program searches are intentionally separate but composable.

## Command-line tools

The original extraction/query tools remain useful for scripting and bulk archaeology.

With `uv`:

```bash
uv sync
```

Extract an EDB:

```bash
uv run mtk-mddb-extract modem.EDB -o out
```

Search an EDB directly:

```bash
uv run mtk-mddb-query modem.EDB IQ_DUMP
uv run mtk-mddb-query modem.EDB URF_TEST_CMD --cf sp --limit 20
```

An extraction contains:

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

The tested MediaTek package places several SSTs under `sp/` while its RocksDB manifest refers to their basenames. Both the CLI and Ghidra plugin create a temporary compatibility view for RocksDB and leave the faithful extraction untouched.

## Format notes

Currently decoded and validated:

- `CATD` section descriptors for `DATAI` / `DATAA`;
- MediaTek's five-byte LZMA1 properties/dictionary prefix followed by a raw LZMA stream;
- the packed-file chain inside `DATAI`;
- reconstruction of the embedded RocksDB directory;
- all RocksDB column families in raw read-only mode;
- the `sp` pool's packed `14-bit bucket + 18-bit byte offset` references;
- the standard enum representation used by `urf_test_cmd_type`: a 23-byte header followed by `count × (u32 value, u32 string_ref)`;
- reverse links from enum record → type record → exposed enum/type names when present.

The extractor rejects path traversal, duplicate archive names, invalid section bounds, inconsistent decompressed sizes, and malformed LZMA properties.

`DATAA` is retained and decoded from LZMA, but its trace/category record format is not yet promoted into a typed UI because it is separate from the RocksDB schema used for the features above.

## Compatibility

Tested against:

- Ghidra 12.2 / Java 25;
- production Fibocom FM350-GL / MediaTek MT6880 firmware family `81600.0000.00.29.23.x`;
- Linux x86-64 locally;
- platform-specific RocksDB JNI release artifacts for Linux, Windows, and macOS are built by CI.

Other MediaTek Catcher/META generations may use related but different layouts. Unsupported or malformed containers should fail loudly instead of being guessed at.

## Development

Python checks:

```bash
uv sync --all-groups
uv run ruff check .
uv run ruff format --check .
uv run ty check
uv run pytest
```

Build the Ghidra extension against an installed Ghidra 12.2:

```bash
export JAVA_HOME=/path/to/jdk-25
export GHIDRA_INSTALL_DIR=/path/to/ghidra_12.2_PUBLIC
./scripts/build_ghidra_extension.sh linux64
```

Pass `linux64`, `win64`, or `osx`; multiple platforms may be supplied to build release artifacts in one invocation.
