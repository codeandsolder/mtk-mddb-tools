# mtk-mddb-tools

Ghidra extension and command-line tools for MediaTek Catcher/META modem databases (`MDDB_*.EDB`).

This started while reverse-engineering a Fibocom FM350-GL / MediaTek T700 modem. The shipping firmware contains a roughly 10 MB `MDDB_InfoCustomAppSrcP_MT6880_*.EDB`; it turns out to be a small `CATD` container around a perfectly ordinary RocksDB:

```text
CATD
├── DATAI  -- raw LZMA1 --> packed RocksDB directory
└── DATAA  -- raw LZMA1 --> companion trace/category metadata
```

On the tested MT6880 database, `DATAI` reconstructs 18 RocksDB column families including `sp`, `trace`, `type`, `struct`, `enum`, `message`, `file`, `l1module`, `l1filter`, and `nvram`.

The Ghidra plugin is the main interface. It opens an EDB directly, searches the database, decodes the common packed string-reference, enum, struct, union, and array representations, maps names back into the current program, follows Ghidra xrefs into code, imports decoded schemas as real Ghidra data types, and can annotate matching code.

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
- typedef-chain and tagged struct/union resolution, including field offsets and field types for the common MDDB layout;
- **Find in Program** for exact firmware string matches;
- **Go to Code Xref** to jump from a matched firmware string to code using Ghidra's reference database;
- **Annotate Program** to add analysis labels, comments, and bookmarks at strings and code xrefs;
- **Import MDDB Type** to materialize a selected decoded struct/union or enum in the current program under `/MediaTek MDDB`, recursively importing nested decoded members and preserving validated array counts.

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

Those names are also keys into the `type` column family. Following the type-alias chain into the tagged `struct` records recovers the concrete IQ payload layouts in the tested MT6880 database:

```c
// URF_TEST_CMD_TRIGGER_IQ_DUMP_MODE_V3 = 0x58
struct u_trigger_iq_dump_mode_v3_req_param_struct { // size 4, align 2
    kal_uint16 enable_iq_dump; // +0x0
    kal_uint16 ant_idx;        // +0x2
};
struct u_trigger_iq_dump_mode_v3_cnf_param_struct { // size 2, align 2
    kal_uint16 dump_status;    // +0x0
};

// URF_TEST_CMD_GET_IQ_DUMP_RESULT_V3 = 0x59
struct u_get_iq_dump_result_v3_req_param_struct { // size 1, align 1
    kal_bool get_result;       // +0x0
};
struct u_get_iq_dump_result_v3_cnf_param_struct { // size 4, align 2
    kal_uint16 is_data_ready;       // +0x0
    kal_uint16 data_section_length; // +0x2
};
```

The result PDU resolves one level further. `u_get_iq_dump_result_v3_cnf_pdu_struct` is 32,768 bytes and contains `UTSTCnfGetIqDumpResultV3pb iq_dump_result[8192]`. The element type is exactly four bytes:

```c
struct UTSTCnfGetIqDumpResultV3pb {
    kal_int16 i_data; // +0x0
    kal_int16 q_data; // +0x2
};
```

So the shipping MDDB explicitly describes a result buffer of **8192 complex signed-16-bit I/Q samples**. The array count comes from the array field descriptor (`0x2000`), not from guessing based on the 32 KiB total size.

Selecting that schema result and clicking **Import MDDB Type** creates `/MediaTek MDDB/u_get_iq_dump_result_v3_cnf_pdu_struct` as a real 32 KiB Ghidra structure containing an 8192-element array of the real four-byte `UTSTCnfGetIqDumpResultV3pb` structure. Selecting the IQ command enum member similarly imports `/MediaTek MDDB/urf_test_cmd_type`; on the tested database it contains 105 members, including `0x58` and `0x59`. The importer maps common MediaTek scalar typedefs to Ghidra integer/boolean types and uses exact-size undefined fields for types that have not yet been decoded.

The plugin derives these from MDDB rather than hard-coding the names. Unknown generations or record layouts still stay raw instead of being guessed.

### Program integration tested on FM350

Against a fully analyzed nanoMIPS FM350 image, the plugin's bridge from MDDB/debug vocabulary to Ghidra code was exercised end-to-end. For example:

- `dhl_inject_string`: 3 MDDB hits, 4 firmware string occurrences, 1 code xref at `0x9021cb94`;
- `NL1_RXDFE_TRIGGER_IQ_DUMP`: 2 firmware occurrences and a code xref at `0x90dc52b2`.

The latter string is present in the firmware rather than this particular MDDB build, which is why the database and program searches are intentionally separate but composable. Data-type import was also exercised against a disposable copy of the analyzed FM350 project: Ghidra independently reported a 32,768-byte IQ-result PDU, an 8192-element array with four-byte elements, `i_data`/`q_data` at offsets 0/2, and a 105-member RF-test enum with the expected `0x58`/`0x59` values. The canonical analysis project was not modified by that test.

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
- reverse links from enum record → type record → exposed enum/type names when present;
- type-alias chains whose packed string refs are themselves `type` keys;
- tagged struct/union keys (`0x61 || string_ref` / `0x62 || string_ref`) and the common field descriptors used by the tested MT6880 database.

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
