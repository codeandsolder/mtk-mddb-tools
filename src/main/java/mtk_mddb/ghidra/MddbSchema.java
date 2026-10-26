package mtk_mddb.ghidra;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.rocksdb.ColumnFamilyHandle;
import org.rocksdb.RocksDB;
import org.rocksdb.RocksDBException;
import org.rocksdb.RocksIterator;

final class MddbSchema {
    private static final int TYPE_CHAIN_LIMIT = 16;
    private static final int STRUCT_HEADER_SIZE = 13;
    private static final int FIELD_DESCRIPTOR_SIZE = 25;

    private record EnumMemberBase(byte[] enumRecordKey, long value) {}

    record EnumMember(String enumName, long value, String memberName, String enumRecordKey) {
        String summary() {
            String prefix = enumName == null || enumName.isBlank() ? "enum " + enumRecordKey : enumName;
            return prefix + " = 0x" + Long.toHexString(value);
        }
    }

    private record StructField(long offset, String typeName, String fieldName) {
        String summary() {
            return String.format("+0x%x %s %s", offset, typeName, fieldName);
        }
    }

    private record StructLayout(String kind, long size, long alignment, List<StructField> fields) {
        String summary() {
            StringBuilder out = new StringBuilder(kind);
            if (size <= 0x100000 && alignment <= 0x10000) {
                out.append(" size=").append(size).append(" align=").append(alignment);
            }
            if (!fields.isEmpty()) {
                out.append(" { ");
                for (int i = 0; i < fields.size(); i++) {
                    if (i != 0) {
                        out.append("; ");
                    }
                    out.append(fields.get(i).summary());
                }
                out.append(" }");
            }
            return out.toString();
        }
    }

    private final RocksDB db;
    private final ColumnFamilyHandle sp;
    private final ColumnFamilyHandle enums;
    private final ColumnFamilyHandle types;
    private final ColumnFamilyHandle structs;
    private final Map<Integer, List<EnumMemberBase>> enumMembersByStringRef = new HashMap<>();
    private final Map<String, String> enumNameCache = new HashMap<>();
    private final Map<Integer, String> typeSummaryCache = new HashMap<>();
    private boolean enumIndexBuilt;

    MddbSchema(RocksDB db, ColumnFamilyHandle sp, ColumnFamilyHandle enums,
            ColumnFamilyHandle types, ColumnFamilyHandle structs) {
        this.db = db;
        this.sp = sp;
        this.enums = enums;
        this.types = types;
        this.structs = structs;
    }

    String decodeStringRef(int ref) throws RocksDBException {
        int bucket = ref & 0x3fff;
        int offset = ref >>> 14;
        byte[] value = db.get(sp, le32(bucket));
        if (value == null || offset >= value.length) {
            return null;
        }
        if (offset > 0 && value[offset - 1] != 0) {
            return null;
        }
        int end = offset;
        while (end < value.length && value[end] != 0) {
            end++;
        }
        if (end == offset || end == value.length) {
            return null;
        }
        return new String(value, offset, end - offset, StandardCharsets.UTF_8);
    }

    int stringRef(int bucket, int offset) {
        if ((bucket & ~0x3fff) != 0 || offset < 0 || offset > 0x3ffff) {
            throw new IllegalArgumentException("String-pool reference is out of range");
        }
        return (offset << 14) | bucket;
    }

    List<EnumMember> findEnumMembers(int packedStringRef) throws RocksDBException {
        ensureEnumIndex();
        List<EnumMemberBase> bases = enumMembersByStringRef.getOrDefault(packedStringRef, List.of());
        if (bases.isEmpty()) {
            return List.of();
        }
        String memberName = decodeStringRef(packedStringRef);
        List<EnumMember> out = new ArrayList<>(bases.size());
        for (EnumMemberBase base : bases) {
            String keyHex = HexFormat.of().formatHex(base.enumRecordKey());
            out.add(new EnumMember(findEnumName(base.enumRecordKey()), base.value(), memberName, keyHex));
        }
        return out;
    }

    synchronized String describeSpMatch(byte[] spKey, int offset) throws RocksDBException {
        if (spKey.length != 4) {
            return "";
        }
        int bucket = u32(spKey, 0);
        if (bucket < 0 || bucket > 0x3fff || offset < 0 || offset > 0x3ffff) {
            return "";
        }
        int ref = stringRef(bucket, offset);
        LinkedHashSet<String> summaries = new LinkedHashSet<>();
        for (EnumMember member : findEnumMembers(ref)) {
            summaries.add(member.summary());
        }
        String typeSummary = describeType(ref);
        if (!typeSummary.isBlank()) {
            summaries.add(typeSummary);
        }
        return String.join("; ", summaries);
    }

    private String describeType(int startRef) throws RocksDBException {
        if (typeSummaryCache.containsKey(startRef)) {
            return typeSummaryCache.get(startRef);
        }

        List<String> names = new ArrayList<>();
        Set<Integer> seen = new LinkedHashSet<>();
        int currentRef = startRef;
        StructLayout layout = null;

        for (int depth = 0; depth < TYPE_CHAIN_LIMIT && seen.add(currentRef); depth++) {
            String name = decodeStringRef(currentRef);
            if (name == null || name.isBlank()) {
                break;
            }
            names.add(name);

            byte[] typeRecord = db.get(types, le32(currentRef));
            if (typeRecord == null) {
                layout = findStructLayout(currentRef, name);
                break;
            }
            if (typeRecord.length < 4) {
                break;
            }
            int nextRef = u32(typeRecord, typeRecord.length - 4);
            String nextName = decodeStringRef(nextRef);
            if (nextName == null || nextName.isBlank()) {
                break;
            }
            currentRef = nextRef;
        }

        if (layout == null) {
            typeSummaryCache.put(startRef, "");
            return "";
        }

        List<String> publicNames = names.stream()
            .filter(name -> !name.startsWith("struct_") && !name.startsWith("union_"))
            .distinct()
            .toList();
        String prefix = publicNames.isEmpty() ? "" : String.join(" -> ", publicNames) + ": ";
        String result = prefix + layout.summary();
        typeSummaryCache.put(startRef, result);
        return result;
    }

    private StructLayout findStructLayout(int ref, String name) throws RocksDBException {
        if (name.startsWith("struct_")) {
            return parseStructRecord(db.get(structs, taggedKey(0x61, ref)), "struct");
        }
        if (name.startsWith("union_")) {
            return parseStructRecord(db.get(structs, taggedKey(0x62, ref)), "union");
        }
        StructLayout layout = parseStructRecord(db.get(structs, taggedKey(0x61, ref)), "struct");
        return layout != null ? layout : parseStructRecord(db.get(structs, taggedKey(0x62, ref)), "union");
    }

    private StructLayout parseStructRecord(byte[] value, String kind) throws RocksDBException {
        if (value == null || value.length < STRUCT_HEADER_SIZE) {
            return null;
        }
        long size = Integer.toUnsignedLong(u32(value, 1));
        long alignment = Integer.toUnsignedLong(u32(value, 5));
        List<StructField> fields = new ArrayList<>();
        Set<String> seenFields = new LinkedHashSet<>();

        for (int at = STRUCT_HEADER_SIZE; at + FIELD_DESCRIPTOR_SIZE <= value.length; at++) {
            long descriptorKind = Integer.toUnsignedLong(u32(value, at + 1));
            if ((descriptorKind & 0xff000000L) != 0x10000000L) {
                continue;
            }
            long fieldOffset = Integer.toUnsignedLong(u32(value, at + 13));
            int typeRef = u32(value, at + 17);
            int nameRef = u32(value, at + 21);
            String typeName = decodeStringRef(typeRef);
            String fieldName = decodeStringRef(nameRef);
            if (!looksIdentifier(typeName) || !looksIdentifier(fieldName)) {
                continue;
            }
            if (fieldOffset > 0x1000000L) {
                continue;
            }
            String identity = fieldOffset + "\u0000" + typeName + "\u0000" + fieldName;
            if (seenFields.add(identity)) {
                fields.add(new StructField(fieldOffset, typeName, fieldName));
            }
            at += FIELD_DESCRIPTOR_SIZE - 1;
        }
        return new StructLayout(kind, size, alignment, List.copyOf(fields));
    }

    private static boolean looksIdentifier(String value) {
        if (value == null || value.isEmpty()) {
            return false;
        }
        char first = value.charAt(0);
        if (!(Character.isLetter(first) || first == '_')) {
            return false;
        }
        for (int i = 1; i < value.length(); i++) {
            char ch = value.charAt(i);
            if (!(Character.isLetterOrDigit(ch) || ch == '_' || ch == ':')) {
                return false;
            }
        }
        return true;
    }

    private void ensureEnumIndex() throws RocksDBException {
        if (enumIndexBuilt) {
            return;
        }
        try (RocksIterator it = db.newIterator(enums)) {
            for (it.seekToFirst(); it.isValid(); it.next()) {
                byte[] value = it.value();
                if (value.length < 23 || (value.length - 23) % 8 != 0) {
                    continue;
                }
                long count = Integer.toUnsignedLong(u32(value, 19));
                if (count != (value.length - 23L) / 8L) {
                    continue;
                }
                byte[] enumKey = it.key().clone();
                for (int at = 23; at + 8 <= value.length; at += 8) {
                    long enumValue = Integer.toUnsignedLong(u32(value, at));
                    int ref = u32(value, at + 4);
                    enumMembersByStringRef.computeIfAbsent(ref, ignored -> new ArrayList<>())
                        .add(new EnumMemberBase(enumKey, enumValue));
                }
            }
            it.status();
        }
        enumIndexBuilt = true;
    }

    private String findEnumName(byte[] enumRecordKey) throws RocksDBException {
        String enumKeyHex = HexFormat.of().formatHex(enumRecordKey);
        if (enumNameCache.containsKey(enumKeyHex)) {
            return enumNameCache.get(enumKeyHex);
        }
        LinkedHashSet<String> names = new LinkedHashSet<>();
        try (RocksIterator typeIt = db.newIterator(types)) {
            for (typeIt.seekToFirst(); typeIt.isValid(); typeIt.next()) {
                byte[] typeKey = typeIt.key();
                if (indexOf(typeIt.value(), enumRecordKey, 0) < 0) {
                    continue;
                }
                findNamesFollowingTypeKey(typeKey, names);
            }
            typeIt.status();
        }
        String result = names.isEmpty() ? null : String.join(" | ", names);
        enumNameCache.put(enumKeyHex, result);
        return result;
    }

    private void findNamesFollowingTypeKey(byte[] typeKey, LinkedHashSet<String> names)
            throws RocksDBException {
        try (RocksIterator structIt = db.newIterator(structs)) {
            for (structIt.seekToFirst(); structIt.isValid(); structIt.next()) {
                byte[] value = structIt.value();
                int from = 0;
                while (from <= value.length - typeKey.length - 4) {
                    int at = indexOf(value, typeKey, from);
                    if (at < 0) {
                        break;
                    }
                    int refAt = at + typeKey.length;
                    if (refAt + 4 <= value.length) {
                        String decoded = decodeStringRef(u32(value, refAt));
                        if (decoded != null && !decoded.isBlank()) {
                            names.add(decoded);
                        }
                    }
                    from = at + 1;
                }
            }
            structIt.status();
        }
    }

    private static byte[] taggedKey(int tag, int ref) {
        byte[] key = new byte[5];
        key[0] = (byte) tag;
        byte[] refBytes = le32(ref);
        System.arraycopy(refBytes, 0, key, 1, refBytes.length);
        return key;
    }

    private static byte[] le32(int value) {
        return ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt(value).array();
    }

    private static int u32(byte[] data, int offset) {
        return ByteBuffer.wrap(data, offset, 4).order(ByteOrder.LITTLE_ENDIAN).getInt();
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
}
