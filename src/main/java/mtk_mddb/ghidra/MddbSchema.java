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

import org.rocksdb.ColumnFamilyHandle;
import org.rocksdb.RocksDB;
import org.rocksdb.RocksDBException;
import org.rocksdb.RocksIterator;

final class MddbSchema {
    private record EnumMemberBase(byte[] enumRecordKey, long value) {}

    record EnumMember(String enumName, long value, String memberName, String enumRecordKey) {
        String summary() {
            String prefix = enumName == null || enumName.isBlank() ? "enum " + enumRecordKey : enumName;
            return prefix + " = 0x" + Long.toHexString(value);
        }
    }

    private final RocksDB db;
    private final ColumnFamilyHandle sp;
    private final ColumnFamilyHandle enums;
    private final ColumnFamilyHandle types;
    private final ColumnFamilyHandle structs;
    private final Map<Integer, List<EnumMemberBase>> enumMembersByStringRef = new HashMap<>();
    private final Map<String, String> enumNameCache = new HashMap<>();
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
        List<EnumMember> members = findEnumMembers(stringRef(bucket, offset));
        if (members.isEmpty()) {
            return "";
        }
        LinkedHashSet<String> summaries = new LinkedHashSet<>();
        for (EnumMember member : members) {
            summaries.add(member.summary());
        }
        return String.join("; ", summaries);
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
