package mtk_mddb.ghidra;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.rocksdb.ColumnFamilyDescriptor;
import org.rocksdb.ColumnFamilyHandle;
import org.rocksdb.Options;
import org.rocksdb.RocksDB;

class MddbSchemaTest {
    static {
        RocksDB.loadLibrary();
    }

    @TempDir
    Path tempDir;

    @Test
    void resolvesPackedStringRefThroughEnumAndTypeName() throws Exception {
        try (Options options = new Options().setCreateIfMissing(true);
             RocksDB db = RocksDB.open(options, tempDir.resolve("db").toString());
             ColumnFamilyHandle sp = db.createColumnFamily(cf("sp"));
             ColumnFamilyHandle enums = db.createColumnFamily(cf("enum"));
             ColumnFamilyHandle types = db.createColumnFamily(cf("type"));
             ColumnFamilyHandle structs = db.createColumnFamily(cf("struct"))) {

            byte[] pool = "TEST_MEMBER\0TEST_ENUM\0".getBytes(StandardCharsets.UTF_8);
            db.put(sp, le32(1), pool);
            int memberRef = packStringRef(1, 0);
            int enumNameRef = packStringRef(1, "TEST_MEMBER\0".length());

            byte[] enumKey = le32(0x10);
            ByteBuffer enumRecord = ByteBuffer.allocate(31).order(ByteOrder.LITTLE_ENDIAN);
            enumRecord.position(19).putInt(1).putInt(0x58).putInt(memberRef);
            db.put(enums, enumKey, enumRecord.array());

            byte[] typeKey = le32(0x20);
            db.put(types, typeKey, enumKey);
            ByteBuffer structRecord = ByteBuffer.allocate(8).order(ByteOrder.LITTLE_ENDIAN);
            structRecord.put(typeKey).putInt(enumNameRef);
            db.put(structs, le32(0x30), structRecord.array());

            MddbSchema schema = new MddbSchema(db, sp, enums, types, structs);
            assertEquals("TEST_ENUM = 0x58", schema.describeSpMatch(le32(1), 0));
        }
    }

    private static ColumnFamilyDescriptor cf(String name) {
        return new ColumnFamilyDescriptor(name.getBytes(StandardCharsets.UTF_8));
    }

    private static int packStringRef(int bucket, int offset) {
        return (offset << 14) | bucket;
    }

    private static byte[] le32(int value) {
        return ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt(value).array();
    }
}
