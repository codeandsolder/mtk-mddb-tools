package mtk_mddb.ghidra;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.Set;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.rocksdb.ColumnFamilyDescriptor;
import org.rocksdb.ColumnFamilyHandle;
import org.rocksdb.ColumnFamilyOptions;
import org.rocksdb.Options;
import org.rocksdb.RocksDB;

class MddbDatabaseDiffTest {
    static {
        RocksDB.loadLibrary();
    }

    @TempDir
    Path tempDir;

    @Test
    void comparesRawColumnFamiliesStringPoolsAndSemanticEnums() throws Exception {
        Path leftPath = tempDir.resolve("left");
        Path rightPath = tempDir.resolve("right");
        createDb(leftPath, "COMMON\0LEFT_ONLY\0TEST_ENUM\0VALUE_A\0VALUE_B\0", true);
        createDb(rightPath, "COMMON\0RIGHT_ONLY\0TEST_ENUM\0VALUE_A\0VALUE_B\0", false);

        try (MddbDatabase left = MddbDatabase.open(leftPath);
             MddbDatabase right = MddbDatabase.open(rightPath)) {
            Set<String> leftStrings = left.stringPoolStrings(4, 64);
            Set<String> rightStrings = right.stringPoolStrings(4, 64);
            assertTrue(leftStrings.contains("COMMON"));
            assertTrue(leftStrings.contains("LEFT_ONLY"));
            assertTrue(rightStrings.contains("RIGHT_ONLY"));

            MddbDatabase.ColumnFamilyDiff sp = left.compareRaw(right).get("sp");
            assertEquals(1, sp.leftRecords());
            assertEquals(1, sp.rightRecords());
            assertEquals(1, sp.commonKeys());
            assertEquals(0, sp.identicalValues());
            assertEquals(1, sp.changedValues());

            MddbDatabase.ColumnFamilyDiff trace = left.compareRaw(right).get("trace");
            assertEquals(2, trace.leftRecords());
            assertEquals(2, trace.rightRecords());
            assertEquals(1, trace.commonKeys());
            assertEquals(1, trace.identicalValues());
            assertEquals(1, trace.onlyLeft());
            assertEquals(1, trace.onlyRight());

            MddbDatabase.SemanticEnumDiff enums = left.compareSemanticEnums(right);
            assertEquals(1, enums.leftEnums());
            assertEquals(1, enums.rightEnums());
            assertEquals(1, enums.commonNames());
            assertEquals(0, enums.identicalEnums());
            assertEquals(1, enums.changedEnums());
            assertEquals(java.util.List.of("TEST_ENUM"), enums.changedNames());
            MddbDatabase.SemanticEnumChange change = enums.changes().get(0);
            assertEquals(4, change.leftSize());
            assertEquals(4, change.rightSize());
            assertEquals(java.util.List.of(), change.removedMembers());
            assertEquals(java.util.List.of(), change.addedMembers());
            assertEquals(java.util.List.of("VALUE_B:2->3"), change.renumberedMembers());
        }
    }

    private static void createDb(Path path, String pool, boolean left) throws Exception {
        try (Options options = new Options().setCreateIfMissing(true);
             RocksDB db = RocksDB.open(options, path.toString());
             ColumnFamilyOptions spOptions = new ColumnFamilyOptions();
             ColumnFamilyOptions traceOptions = new ColumnFamilyOptions();
             ColumnFamilyOptions enumOptions = new ColumnFamilyOptions();
             ColumnFamilyOptions typeOptions = new ColumnFamilyOptions();
             ColumnFamilyOptions structOptions = new ColumnFamilyOptions();
             ColumnFamilyHandle sp = db.createColumnFamily(
                 new ColumnFamilyDescriptor("sp".getBytes(StandardCharsets.UTF_8), spOptions));
             ColumnFamilyHandle trace = db.createColumnFamily(
                 new ColumnFamilyDescriptor("trace".getBytes(StandardCharsets.UTF_8), traceOptions));
             ColumnFamilyHandle enums = db.createColumnFamily(
                 new ColumnFamilyDescriptor("enum".getBytes(StandardCharsets.UTF_8), enumOptions));
             ColumnFamilyHandle types = db.createColumnFamily(
                 new ColumnFamilyDescriptor("type".getBytes(StandardCharsets.UTF_8), typeOptions));
             ColumnFamilyHandle structs = db.createColumnFamily(
                 new ColumnFamilyDescriptor("struct".getBytes(StandardCharsets.UTF_8), structOptions))) {
            byte[] poolBytes = pool.getBytes(StandardCharsets.UTF_8);
            db.put(sp, le32(1), poolBytes);
            db.put(trace, new byte[] {1}, new byte[] {9});
            db.put(trace, new byte[] {(byte) (left ? 2 : 3)}, new byte[] {8});

            int enumName = stringRef(1, indexOf(poolBytes, "TEST_ENUM"));
            int valueA = stringRef(1, indexOf(poolBytes, "VALUE_A"));
            int valueB = stringRef(1, indexOf(poolBytes, "VALUE_B"));
            byte[] enumKey = le32(0x40);
            ByteBuffer enumRecord = ByteBuffer.allocate(39).order(ByteOrder.LITTLE_ENDIAN);
            enumRecord.putInt(19, 2);
            enumRecord.position(23)
                .putInt(1).putInt(valueA)
                .putInt(left ? 2 : 3).putInt(valueB);
            db.put(enums, enumKey, enumRecord.array());

            ByteBuffer typeRecord = ByteBuffer.allocate(13).order(ByteOrder.LITTLE_ENDIAN);
            typeRecord.putInt(5, 4);
            typeRecord.position(9).put(enumKey);
            db.put(types, le32(enumName), typeRecord.array());
            // Presence of the struct CF enables the full schema decoder; this test needs no records.
            assertTrue(structs.isOwningHandle());
        }
    }

    private static int indexOf(byte[] data, String text) {
        byte[] needle = text.getBytes(StandardCharsets.UTF_8);
        outer: for (int i = 0; i <= data.length - needle.length; i++) {
            for (int j = 0; j < needle.length; j++) {
                if (data[i + j] != needle[j]) {
                    continue outer;
                }
            }
            return i;
        }
        throw new IllegalArgumentException("missing test string " + text);
    }

    private static int stringRef(int bucket, int offset) {
        return (offset << 14) | bucket;
    }

    private static byte[] le32(int value) {
        return ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt(value).array();
    }
}
