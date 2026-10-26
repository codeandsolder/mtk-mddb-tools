package mtk_mddb.ghidra;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.rocksdb.ColumnFamilyDescriptor;
import org.rocksdb.ColumnFamilyHandle;
import org.rocksdb.ColumnFamilyOptions;
import org.rocksdb.DBOptions;
import org.rocksdb.Options;
import org.rocksdb.RocksDB;
import org.rocksdb.RocksDBException;
import org.rocksdb.RocksIterator;

public final class MddbDatabase implements AutoCloseable {
    static {
        RocksDB.loadLibrary();
    }

    private final EdbWorkspace workspace;
    private final DBOptions dbOptions;
    private final RocksDB db;
    private final List<ColumnFamilyOptions> cfOptions;
    private final Map<String, ColumnFamilyHandle> handles;
    private final MddbSchema schema;

    private MddbDatabase(EdbWorkspace workspace, DBOptions dbOptions, RocksDB db,
            List<ColumnFamilyOptions> cfOptions, Map<String, ColumnFamilyHandle> handles) {
        this.workspace = workspace;
        this.dbOptions = dbOptions;
        this.db = db;
        this.cfOptions = cfOptions;
        this.handles = handles;
        ColumnFamilyHandle sp = handles.get("sp");
        ColumnFamilyHandle enums = handles.get("enum");
        ColumnFamilyHandle types = handles.get("type");
        ColumnFamilyHandle structs = handles.get("struct");
        this.schema = sp != null && enums != null && types != null && structs != null
            ? new MddbSchema(db, sp, enums, types, structs)
            : null;
    }

    public static MddbDatabase open(Path source) throws IOException, RocksDBException {
        EdbWorkspace workspace = EdbWorkspace.open(source);
        try {
            Path root = workspace.rocksDbRoot();
            List<byte[]> names;
            try (Options options = new Options()) {
                names = RocksDB.listColumnFamilies(options, root.toString());
            }
            if (names == null || names.isEmpty()) {
                throw new IOException("Embedded RocksDB has no column families");
            }

            List<ColumnFamilyDescriptor> descriptors = new ArrayList<>();
            List<ColumnFamilyOptions> cfOptions = new ArrayList<>();
            for (byte[] name : names) {
                ColumnFamilyOptions options = new ColumnFamilyOptions();
                cfOptions.add(options);
                descriptors.add(new ColumnFamilyDescriptor(name, options));
            }
            List<ColumnFamilyHandle> openedHandles = new ArrayList<>();
            DBOptions dbOptions = new DBOptions().setCreateIfMissing(false);
            RocksDB db = RocksDB.openReadOnly(dbOptions, root.toString(), descriptors, openedHandles);
            Map<String, ColumnFamilyHandle> byName = new LinkedHashMap<>();
            for (int i = 0; i < names.size(); i++) {
                byName.put(new String(names.get(i), StandardCharsets.UTF_8), openedHandles.get(i));
            }
            return new MddbDatabase(workspace, dbOptions, db, cfOptions, byName);
        } catch (IOException | RocksDBException | RuntimeException e) {
            workspace.close();
            throw e;
        }
    }

    public List<String> columnFamilies() {
        return Collections.unmodifiableList(new ArrayList<>(handles.keySet()));
    }

    public int dataASize() {
        return workspace.dataASize();
    }

    public String schemaInfo(MddbSearchResult result) throws RocksDBException {
        if (schema == null || !result.columnFamily().equals("sp") || !result.field().equals("value")) {
            return "";
        }
        return schema.describeSpMatch(result.key(), result.offset());
    }

    public List<MddbSearchResult> search(String needleText, String columnFamily, int limit) throws RocksDBException {
        byte[] needle = needleText.getBytes(StandardCharsets.UTF_8);
        if (needle.length == 0) {
            return List.of();
        }
        List<MddbSearchResult> out = new ArrayList<>();
        Iterable<Map.Entry<String, ColumnFamilyHandle>> selected;
        if (columnFamily == null || columnFamily.equals("All")) {
            selected = handles.entrySet();
        } else {
            ColumnFamilyHandle handle = handles.get(columnFamily);
            if (handle == null) {
                throw new IllegalArgumentException("Unknown column family: " + columnFamily);
            }
            selected = List.of(Map.entry(columnFamily, handle));
        }

        for (Map.Entry<String, ColumnFamilyHandle> entry : selected) {
            try (RocksIterator it = db.newIterator(entry.getValue())) {
                for (it.seekToFirst(); it.isValid(); it.next()) {
                    byte[] key = it.key();
                    byte[] value = it.value();
                    collectMatches(out, entry.getKey(), "key", key, key, needle, limit);
                    if (out.size() >= limit) {
                        return out;
                    }
                    collectMatches(out, entry.getKey(), "value", key, value, needle, limit);
                    if (out.size() >= limit) {
                        return out;
                    }
                }
                it.status();
            }
        }
        return out;
    }

    private static void collectMatches(List<MddbSearchResult> out, String cf, String field,
            byte[] key, byte[] data, byte[] needle, int limit) {
        int from = 0;
        while (from <= data.length - needle.length && out.size() < limit) {
            int hit = indexOf(data, needle, from);
            if (hit < 0) {
                return;
            }
            out.add(new MddbSearchResult(cf, field, key.clone(), hit, data.clone()));
            from = hit + 1;
        }
    }

    static String renderContext(MddbSearchResult result, int context, int needleLength) {
        byte[] data = result.value();
        int start = Math.max(0, result.offset() - context);
        int end = Math.min(data.length, result.offset() + needleLength + context);
        StringBuilder out = new StringBuilder((end - start) * 2);
        for (int i = start; i < end; i++) {
            int value = Byte.toUnsignedInt(data[i]);
            if (value >= 32 && value < 127) {
                out.append((char) value);
            } else if (value == 0) {
                out.append("\\0");
            } else if (value == 10) {
                out.append("\\n");
            } else if (value == 13) {
                out.append("\\r");
            } else if (value == 9) {
                out.append("\\t");
            } else {
                out.append(String.format("\\x%02x", value));
            }
        }
        return out.toString();
    }

    private static int indexOf(byte[] data, byte[] needle, int start) {
        outer: for (int i = start; i <= data.length - needle.length; i++) {
            for (int j = 0; j < needle.length; j++) {
                if (data[i + j] != needle[j]) {
                    continue outer;
                }
            }
            return i;
        }
        return -1;
    }

    @Override
    public void close() throws IOException {
        for (ColumnFamilyHandle handle : handles.values()) {
            handle.close();
        }
        db.close();
        for (ColumnFamilyOptions options : cfOptions) {
            options.close();
        }
        dbOptions.close();
        workspace.close();
    }
}
