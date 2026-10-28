package mtk_mddb.ghidra;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.rocksdb.ColumnFamilyDescriptor;
import org.rocksdb.ColumnFamilyHandle;
import org.rocksdb.ColumnFamilyOptions;
import org.rocksdb.DBOptions;
import org.rocksdb.Options;
import org.rocksdb.RocksDB;
import org.rocksdb.RocksDBException;
import org.rocksdb.RocksIterator;

public final class MddbDatabase implements AutoCloseable {
    public record ColumnFamilyDiff(long leftRecords, long rightRecords, long commonKeys,
            long identicalValues, long changedValues, long onlyLeft, long onlyRight) {}

    public record SemanticEnumChange(String name, int leftSize, int rightSize,
            List<String> removedMembers, List<String> addedMembers,
            List<String> renumberedMembers) {}

    public record SemanticEnumDiff(int leftEnums, int rightEnums, int commonNames,
            int identicalEnums, int changedEnums, int onlyLeft, int onlyRight,
            List<SemanticEnumChange> changes, List<String> onlyLeftNames,
            List<String> onlyRightNames) {
        public List<String> changedNames() {
            return changes.stream().map(SemanticEnumChange::name).toList();
        }
    }

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

    MddbSchema.ResolvedType resolvedType(MddbSearchResult result) throws RocksDBException {
        if (schema == null || !result.columnFamily().equals("sp") || !result.field().equals("value")) {
            return null;
        }
        return schema.resolveTypeForSpMatch(result.key(), result.offset());
    }

    MddbSchema.ResolvedType resolvedTypeByName(String name) throws RocksDBException {
        return schema == null ? null : schema.resolveTypeByName(name);
    }

    MddbSchema.EnumDefinition resolvedEnumByName(String name) throws RocksDBException {
        return schema == null ? null : schema.resolveEnumByName(name);
    }

    List<MddbSchema.EnumDefinition> enumDefinitions(MddbSearchResult result) throws RocksDBException {
        if (schema == null || !result.columnFamily().equals("sp") || !result.field().equals("value")) {
            return List.of();
        }
        return schema.enumDefinitionsForSpMatch(result.key(), result.offset());
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

    public Map<String, String> semanticEnumSignatures() throws RocksDBException {
        return schema == null ? Map.of() : schema.semanticEnumSignatures();
    }

    public SemanticEnumDiff compareSemanticEnums(MddbDatabase other) throws RocksDBException {
        Map<String, String> left = semanticEnumSignatures();
        Map<String, String> right = other.semanticEnumSignatures();
        LinkedHashSet<String> names = new LinkedHashSet<>(left.keySet());
        names.addAll(right.keySet());
        int common = 0;
        int identical = 0;
        List<SemanticEnumChange> changes = new ArrayList<>();
        List<String> onlyLeft = new ArrayList<>();
        List<String> onlyRight = new ArrayList<>();
        for (String name : names) {
            String a = left.get(name);
            String b = right.get(name);
            if (a == null) {
                onlyRight.add(name);
            } else if (b == null) {
                onlyLeft.add(name);
            } else {
                common++;
                if (a.equals(b)) {
                    identical++;
                } else {
                    changes.add(enumChange(name, a, b));
                }
            }
        }
        changes.sort(java.util.Comparator.comparing(SemanticEnumChange::name));
        Collections.sort(onlyLeft);
        Collections.sort(onlyRight);
        return new SemanticEnumDiff(left.size(), right.size(), common, identical, changes.size(),
            onlyLeft.size(), onlyRight.size(), List.copyOf(changes), List.copyOf(onlyLeft),
            List.copyOf(onlyRight));
    }

    private static SemanticEnumChange enumChange(String name, String left, String right) {
        EnumSignature a = parseEnumSignature(left);
        EnumSignature b = parseEnumSignature(right);
        List<String> removed = new ArrayList<>();
        List<String> added = new ArrayList<>();
        List<String> renumbered = new ArrayList<>();
        for (Map.Entry<String, String> entry : a.valuesByName().entrySet()) {
            String rightValue = b.valuesByName().get(entry.getKey());
            if (rightValue == null) {
                removed.add(entry.getValue() + "=" + entry.getKey());
            } else if (!entry.getValue().equals(rightValue)) {
                renumbered.add(entry.getKey() + ":" + entry.getValue() + "->" + rightValue);
            }
        }
        for (Map.Entry<String, String> entry : b.valuesByName().entrySet()) {
            if (!a.valuesByName().containsKey(entry.getKey())) {
                added.add(entry.getValue() + "=" + entry.getKey());
            }
        }
        return new SemanticEnumChange(name, a.size(), b.size(), List.copyOf(removed),
            List.copyOf(added), List.copyOf(renumbered));
    }

    private record EnumSignature(int size, Map<String, String> valuesByName) {}

    private static EnumSignature parseEnumSignature(String signature) {
        int separator = signature.indexOf(':');
        int size = Integer.parseInt(signature.substring(0, separator));
        LinkedHashMap<String, String> values = new LinkedHashMap<>();
        for (String member : signature.substring(separator + 1).split(";")) {
            if (member.isEmpty()) {
                continue;
            }
            int equals = member.indexOf('=');
            values.put(member.substring(equals + 1), member.substring(0, equals));
        }
        return new EnumSignature(size, Collections.unmodifiableMap(values));
    }

    /** Returns printable NUL-terminated strings from the MDDB string pool. */
    public Set<String> stringPoolStrings(int minLength, int maxLength) throws RocksDBException {
        if (minLength < 1 || maxLength < minLength) {
            throw new IllegalArgumentException("Invalid string length bounds");
        }
        ColumnFamilyHandle handle = handles.get("sp");
        if (handle == null) {
            return Set.of();
        }
        LinkedHashSet<String> out = new LinkedHashSet<>();
        try (RocksIterator it = db.newIterator(handle)) {
            for (it.seekToFirst(); it.isValid(); it.next()) {
                byte[] value = it.value();
                int start = 0;
                for (int i = 0; i <= value.length; i++) {
                    if (i != value.length && value[i] != 0) {
                        continue;
                    }
                    int length = i - start;
                    if (length >= minLength && length <= maxLength && isPrintable(value, start, i)) {
                        out.add(new String(value, start, length, StandardCharsets.UTF_8));
                    }
                    start = i + 1;
                }
            }
            it.status();
        }
        return Collections.unmodifiableSet(out);
    }

    /**
     * Compares raw RocksDB records without assuming that build-local keys or string-pool offsets
     * are stable. The result is useful as a structural baseline before semantic schema comparison.
     */
    public Map<String, ColumnFamilyDiff> compareRaw(MddbDatabase other) throws RocksDBException {
        LinkedHashSet<String> names = new LinkedHashSet<>(handles.keySet());
        names.addAll(other.handles.keySet());
        LinkedHashMap<String, ColumnFamilyDiff> out = new LinkedHashMap<>();
        for (String name : names) {
            ColumnFamilyHandle left = handles.get(name);
            ColumnFamilyHandle right = other.handles.get(name);
            if (left == null) {
                long rightCount = countRecords(other.db, right);
                out.put(name, new ColumnFamilyDiff(0, rightCount, 0, 0, 0, 0, rightCount));
            } else if (right == null) {
                long leftCount = countRecords(db, left);
                out.put(name, new ColumnFamilyDiff(leftCount, 0, 0, 0, 0, leftCount, 0));
            } else {
                out.put(name, compareColumnFamily(db, left, other.db, right));
            }
        }
        return Collections.unmodifiableMap(out);
    }

    private static ColumnFamilyDiff compareColumnFamily(RocksDB leftDb, ColumnFamilyHandle left,
            RocksDB rightDb, ColumnFamilyHandle right) throws RocksDBException {
        long leftRecords = 0;
        long rightRecords = 0;
        long commonKeys = 0;
        long identical = 0;
        long changed = 0;
        long onlyLeft = 0;
        long onlyRight = 0;
        try (RocksIterator a = leftDb.newIterator(left); RocksIterator b = rightDb.newIterator(right)) {
            a.seekToFirst();
            b.seekToFirst();
            while (a.isValid() || b.isValid()) {
                if (!a.isValid()) {
                    rightRecords++;
                    onlyRight++;
                    b.next();
                    continue;
                }
                if (!b.isValid()) {
                    leftRecords++;
                    onlyLeft++;
                    a.next();
                    continue;
                }
                int order = compareUnsigned(a.key(), b.key());
                if (order < 0) {
                    leftRecords++;
                    onlyLeft++;
                    a.next();
                } else if (order > 0) {
                    rightRecords++;
                    onlyRight++;
                    b.next();
                } else {
                    leftRecords++;
                    rightRecords++;
                    commonKeys++;
                    if (Arrays.equals(a.value(), b.value())) {
                        identical++;
                    } else {
                        changed++;
                    }
                    a.next();
                    b.next();
                }
            }
            a.status();
            b.status();
        }
        return new ColumnFamilyDiff(leftRecords, rightRecords, commonKeys, identical, changed,
            onlyLeft, onlyRight);
    }

    private static long countRecords(RocksDB database, ColumnFamilyHandle handle)
            throws RocksDBException {
        long count = 0;
        try (RocksIterator it = database.newIterator(handle)) {
            for (it.seekToFirst(); it.isValid(); it.next()) {
                count++;
            }
            it.status();
        }
        return count;
    }

    private static int compareUnsigned(byte[] left, byte[] right) {
        int count = Math.min(left.length, right.length);
        for (int i = 0; i < count; i++) {
            int a = Byte.toUnsignedInt(left[i]);
            int b = Byte.toUnsignedInt(right[i]);
            if (a != b) {
                return Integer.compare(a, b);
            }
        }
        return Integer.compare(left.length, right.length);
    }

    private static boolean isPrintable(byte[] data, int start, int end) {
        for (int i = start; i < end; i++) {
            int value = Byte.toUnsignedInt(data[i]);
            if (value < 0x20 || value == 0x7f) {
                return false;
            }
        }
        return true;
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
