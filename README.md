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
- structural discovery and decoding of the MDDB enum member table across the observed header variants;
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
FT_MESSAGE_ID = 0x43     FT_URF_TEST_REQ_ID
FT_MESSAGE_ID = 0x44     FT_URF_TEST_CNF_ID
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

Selecting that schema result and clicking **Import MDDB Type** creates `/MediaTek MDDB/u_get_iq_dump_result_v3_cnf_pdu_struct` as a real 32 KiB Ghidra structure containing an 8192-element array of the real four-byte `UTSTCnfGetIqDumpResultV3pb` structure. Selecting the IQ command enum member similarly imports `/MediaTek MDDB/URfTestCmdType` (the schema browser also exposes `urf_test_cmd_type` as an alias/tag); on the tested database it contains 105 members, including `0x58` and `0x59`. The importer maps common MediaTek scalar typedefs to Ghidra integer/boolean types and uses exact-size undefined fields for types that have not yet been decoded.

The plugin derives these from MDDB rather than hard-coding the names. Unknown generations or record layouts still stay raw instead of being guessed.

### Program integration tested on FM350

Against a fully analyzed nanoMIPS FM350 image, the plugin's bridge from MDDB/debug vocabulary to Ghidra code was exercised end-to-end. The canonical low-mirror inventory finds two `dhl_inject_string` occurrences (`0x01632104` and `0x01da02e8`) and an existing reference at `0x0021c4ac`. It also finds `NL1_RXDFE_TRIGGER_IQ_DUMP` at `0x016a4558` even though this persisted analysis has no recovered code xref for that generated debug-name string. That distinction is intentional: raw firmware vocabulary is retained independently of Ghidra's current reference recovery.

Runtime-alias references are still followed when they exist. For example, `CCISMRx` is stored in the low mirror but the analyzed reference is in the `0x90000000` runtime alias; the tracer reports the raw high address as well as its canonical low offset. Data-type import was also exercised against a disposable copy of the analyzed FM350 project: Ghidra independently reported a 32,768-byte IQ-result PDU, an 8192-element array with four-byte elements, `i_data`/`q_data` at offsets 0/2, and a 105-member RF-test enum with the expected `0x58`/`0x59` values. The canonical analysis project was not modified by that test.

### Cross-build firmware diff

The MDDB browser also has **Compare EDB...**, which compares RocksDB column-family structure, decoded string-pool vocabulary, and named enum ABIs semantically so build-local keys and string offsets do not masquerade as API changes. Enum changes are normalized by member name and reported as additions, removals, or renumberings; inserting one enum member no longer makes every following numeric value look like an unrelated deletion/addition pair.

For analyzed modem programs, the bundled **CompareMtkBuilds.java** script intersects the two MDDB vocabularies and uses shared strings as semantic anchors into both Ghidra programs. It also inventories raw null-terminated ASCII directly from initialized memory, so strings do not disappear merely because lean auto-analysis failed to define a `StringDataType`. Raw program strings are compared as sets and as constant-address-delta runs, which exposes large relinked regions even when function boundaries move. It FID-hashes all non-thunk functions, reports exact-match coverage, and exports every unique one-to-one full-FID match as an address pair rather than only counting them. An optional BSim pass is restricted to the MDDB-anchored pairs instead of doing a blind all-functions quadratic comparison.

NCC's MediaTek loader maps the same `md1rom` bytes at both a low `mirror` block and a `main` runtime alias at `0x90000000`. The entry point and imported debug symbols live in `mirror`, while absolute modem pointers normally target `main`. Raw strings and Version Tracking use the low mirror once, but FID/string anchoring deduplicates the **union of both function analyses by md1rom offset**: a low/symbolized function wins when both aliases found it, while genuinely runtime-only functions are retained. References are checked through both aliases and report canonical low offsets. Programs without that loader layout fall back to all loaded initialized blocks.

With `--vt`, the same script additionally runs Ghidra's Version Tracking correlators in a transient session: exact byte/instruction/mnemonic matches, conservative operand-based disambiguation of duplicate exact-instruction groups, then function/reference correlation seeded by accepted matches. Duplicate candidates are accepted only when scalar/address operand maps are unique in both directions and the pair actually came from Ghidra's duplicate-instruction match set. The session may accept associations internally so later correlators can use them, but **no markup application task is run**; the comparator also asserts that neither input Program's modification number changed.

On the persisted FM350 full `.17` versus GL16 `.19` corpus, a `-noanalysis --vt` run with the canonical mirror/runtime-alias view found **38,324 shared firmware strings**, **17,225 identical / 88 changed named enums**, **6,762 functions covered by a matching full FID**, **5,654 unique one-to-one full-FID pairs**, **5,631 accepted VT function associations**, and **3,476 accepted VT data associations**. For the RF/debug tracer's current needle set, 40 of 48 referenced source functions map to GL16 by unique FID or accepted VT (39 by each method independently, 38 by both); that includes 14/18 ENDC functions, 20/23 ETDPD functions, the recovered RXDFE function, and all four recovered TXDFE functions. These are validation figures for this corpus, not baked-in matching thresholds or expectations.

The bundled **MtkDiffAnalysis.java** pre-analysis preset keeps function discovery, strings, references, constant propagation and shared-return recovery while disabling decompiler-heavy presentation passes that do not affect this comparison. Use the same preset on both builds for a reproducible corpus.

The bundled **TraceMtkProgramStrings.java** script searches that same raw firmware-string inventory for case-insensitive substrings, reports existing code references, and emits one-hop caller/callee edges for referenced functions. Raw strings with no code xref are preserved in the report rather than silently disappearing; this matters for generated MediaTek feature/trace-name catalogs that exist as metadata rather than ordinary C string literals.

Headless runs accept the target Ghidra project path, source EDB, target EDB, output TSV, plus optional `--bsim` and `--vt` flags. The TSV contains raw column-family deltas, semantic enum/member deltas, a single-pass raw firmware-string vocabulary diff, long identical string runs that moved by a constant address delta, global FID coverage, explicit exact-FID address pairs, MDDB-anchored pairs, and optional Version Tracking / BSim results. The raw-string scanner uses the canonical comparison memory scope rather than only Ghidra-defined strings, so generated feature/debug catalogs survive lean analysis.

For an already-analyzed persisted corpus, pass **`-noanalysis`** to `analyzeHeadless` when running `CompareMtkBuilds.java` or `TraceMtkProgramStrings.java`. Otherwise Ghidra runs auto-analysis again in memory before the post-script—even with `-readOnly`—which can change discovered function/reference sets for that invocation and then discard those changes. Use `MtkDiffAnalysis.java` while creating/updating the corpus; use `-noanalysis` for reproducible comparisons of the saved state. This workflow is intended for normal vendor point releases where linking and layout churn make raw block diffs misleading.

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
- enum member tables as `count × (u32 value, u32 string_ref)`, with the table boundary recovered structurally rather than assuming one header size (the tested database uses 23-, 27-, 35-, and 55-byte variants);
- reverse links from enum record → type record → exposed enum/type names when present;
- type-alias chains whose packed string refs are themselves `type` keys;
- tagged struct/union keys (`0x61 || string_ref` / `0x62 || string_ref`) and the common field descriptors used by the tested MT6880 database.

The extractor rejects path traversal, duplicate archive names, invalid section bounds, inconsistent decompressed sizes, and malformed LZMA properties.

`DATAA` is retained and decoded from LZMA, but its trace/category record format is not yet promoted into a typed UI because it is separate from the RocksDB schema used for the features above.

## Compatibility

Tested against:

- Ghidra 12.2 / Java 25;
- production Fibocom FM350-GL / MediaTek MT6880 firmware family `81600.0000.00.29.23.x`;
- production Fibocom FM350-GL-16 / MediaTek MT6880 firmware family `11600.0000.00.29.23.x`, including cross-build comparison against the `81600` family;
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
