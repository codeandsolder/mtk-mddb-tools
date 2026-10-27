package mtk_mddb.ghidra;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

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
             RocksDB db = RocksDB.open(options, tempDir.resolve("enum-db").toString());
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

            byte[] typeKey = le32(enumNameRef);
            db.put(types, typeKey, enumKey);
            ByteBuffer structRecord = ByteBuffer.allocate(8).order(ByteOrder.LITTLE_ENDIAN);
            structRecord.put(typeKey).putInt(enumNameRef);
            db.put(structs, le32(0x30), structRecord.array());

            MddbSchema schema = new MddbSchema(db, sp, enums, types, structs);
            assertEquals("TEST_ENUM = 0x58", schema.describeSpMatch(le32(1), 0));
            MddbSchema.EnumDefinition enumDefinition =
                schema.enumDefinitionsForSpMatch(le32(1), 0).get(0);
            assertEquals("TEST_ENUM", enumDefinition.name());
            assertEquals(4, enumDefinition.size());
            assertEquals(List.of(new MddbSchema.EnumValue(0x58, "TEST_MEMBER")),
                enumDefinition.values());
            assertEquals("TEST_ENUM", schema.resolveEnumByName("TEST_ENUM").name());
        }
    }

    @Test
    void resolvesThirtyFiveByteEnumHeaderAndRejectsHeaderPseudoMember() throws Exception {
        try (Options options = new Options().setCreateIfMissing(true);
             RocksDB db = RocksDB.open(options, tempDir.resolve("enum-35-db").toString());
             ColumnFamilyHandle sp = db.createColumnFamily(cf("sp"));
             ColumnFamilyHandle enums = db.createColumnFamily(cf("enum"));
             ColumnFamilyHandle types = db.createColumnFamily(cf("type"));
             ColumnFamilyHandle structs = db.createColumnFamily(cf("struct"))) {

            Map<String, Integer> offsets = new LinkedHashMap<>();
            ByteArrayOutputStream pool = new ByteArrayOutputStream();
            for (String value : new String[] {
                    "TEST_REQ_ID", "TEST_CNF_ID", "TEST_OTHER_ID", "TEST_MESSAGE_ID"}) {
                offsets.put(value, pool.size());
                pool.writeBytes(value.getBytes(StandardCharsets.UTF_8));
                pool.write(0);
            }
            db.put(sp, le32(4), pool.toByteArray());

            int reqRef = packStringRef(4, offsets.get("TEST_REQ_ID"));
            int cnfRef = packStringRef(4, offsets.get("TEST_CNF_ID"));
            int otherRef = packStringRef(4, offsets.get("TEST_OTHER_ID"));
            int enumNameRef = packStringRef(4, offsets.get("TEST_MESSAGE_ID"));

            byte[] enumKey = le32(0x40);
            ByteBuffer enumRecord = ByteBuffer.allocate(35 + 3 * 8).order(ByteOrder.LITTLE_ENDIAN);
            // Offset 23 deliberately looks like a second structural candidate: a false
            // 27-byte header with four members. Its first pseudo-member string ref is the
            // real count word at offset 31, so identifier scoring must prefer offset 35.
            enumRecord.putInt(23, 4);
            enumRecord.putInt(31, 3);
            enumRecord.position(35)
                .putInt(0x43).putInt(reqRef)
                .putInt(0x44).putInt(cnfRef)
                .putInt(0x45).putInt(otherRef);
            db.put(enums, enumKey, enumRecord.array());

            byte[] typeKey = le32(enumNameRef);
            db.put(types, typeKey, enumKey);

            MddbSchema schema = new MddbSchema(db, sp, enums, types, structs);
            assertEquals("TEST_MESSAGE_ID = 0x43",
                schema.describeSpMatch(le32(4), offsets.get("TEST_REQ_ID")));
            MddbSchema.EnumDefinition definition = schema.resolveEnumByName("TEST_MESSAGE_ID");
            assertNotNull(definition);
            assertEquals(List.of(
                new MddbSchema.EnumValue(0x43, "TEST_REQ_ID"),
                new MddbSchema.EnumValue(0x44, "TEST_CNF_ID"),
                new MddbSchema.EnumValue(0x45, "TEST_OTHER_ID")), definition.values());
        }
    }

    @Test
    void resolvesTypeAliasesAndStructFields() throws Exception {
        try (Options options = new Options().setCreateIfMissing(true);
             RocksDB db = RocksDB.open(options, tempDir.resolve("struct-db").toString());
             ColumnFamilyHandle sp = db.createColumnFamily(cf("sp"));
             ColumnFamilyHandle enums = db.createColumnFamily(cf("enum"));
             ColumnFamilyHandle types = db.createColumnFamily(cf("type"));
             ColumnFamilyHandle structs = db.createColumnFamily(cf("struct"))) {

            Map<String, Integer> offsets = new LinkedHashMap<>();
            ByteArrayOutputStream pool = new ByteArrayOutputStream();
            for (String value : new String[] {
                    "TEST_ALIAS", "TEST_PAYLOAD", "struct_test_payload",
                    "kal_uint16", "field_a", "field_b"}) {
                offsets.put(value, pool.size());
                pool.writeBytes(value.getBytes(StandardCharsets.UTF_8));
                pool.write(0);
            }
            db.put(sp, le32(2), pool.toByteArray());

            int aliasRef = packStringRef(2, offsets.get("TEST_ALIAS"));
            int payloadRef = packStringRef(2, offsets.get("TEST_PAYLOAD"));
            int structRef = packStringRef(2, offsets.get("struct_test_payload"));
            int uint16Ref = packStringRef(2, offsets.get("kal_uint16"));
            int fieldARef = packStringRef(2, offsets.get("field_a"));
            int fieldBRef = packStringRef(2, offsets.get("field_b"));

            db.put(types, le32(aliasRef), typeAlias(payloadRef));
            db.put(types, le32(payloadRef), typeAlias(structRef));

            ByteBuffer structRecord = ByteBuffer.allocate(13 + 2 * 25).order(ByteOrder.LITTLE_ENDIAN);
            structRecord.put((byte) 0).putInt(4).putInt(2).putInt(0);
            putField(structRecord, 0, uint16Ref, fieldARef);
            putField(structRecord, 2, uint16Ref, fieldBRef);
            db.put(structs, taggedKey(0x61, structRef), structRecord.array());

            MddbSchema schema = new MddbSchema(db, sp, enums, types, structs);
            assertEquals(
                "TEST_ALIAS -> TEST_PAYLOAD: struct size=4 align=2 { " +
                    "+0x0 kal_uint16 field_a; +0x2 kal_uint16 field_b }",
                schema.describeSpMatch(le32(2), offsets.get("TEST_ALIAS")));
            MddbSchema.ResolvedType type = schema.resolveTypeByName("TEST_ALIAS");
            assertNotNull(type);
            assertEquals("TEST_ALIAS", type.name());
            assertEquals(4, type.size());
            assertEquals(2, type.fields().size());
            assertEquals("field_b", type.fields().get(1).fieldName());
        }
    }

    @Test
    void resolvesStructArrayCount() throws Exception {
        try (Options options = new Options().setCreateIfMissing(true);
             RocksDB db = RocksDB.open(options, tempDir.resolve("array-db").toString());
             ColumnFamilyHandle sp = db.createColumnFamily(cf("sp"));
             ColumnFamilyHandle enums = db.createColumnFamily(cf("enum"));
             ColumnFamilyHandle types = db.createColumnFamily(cf("type"));
             ColumnFamilyHandle structs = db.createColumnFamily(cf("struct"))) {

            Map<String, Integer> offsets = new LinkedHashMap<>();
            ByteArrayOutputStream pool = new ByteArrayOutputStream();
            for (String value : new String[] {
                    "TEST_PDU", "struct_test_pdu", "TEST_ELEMENT", "iq_dump_result"}) {
                offsets.put(value, pool.size());
                pool.writeBytes(value.getBytes(StandardCharsets.UTF_8));
                pool.write(0);
            }
            db.put(sp, le32(3), pool.toByteArray());

            int pduRef = packStringRef(3, offsets.get("TEST_PDU"));
            int structRef = packStringRef(3, offsets.get("struct_test_pdu"));
            int elementRef = packStringRef(3, offsets.get("TEST_ELEMENT"));
            int fieldRef = packStringRef(3, offsets.get("iq_dump_result"));
            db.put(types, le32(pduRef), typeAlias(structRef));

            ByteBuffer structRecord = ByteBuffer.allocate(13 + 29).order(ByteOrder.LITTLE_ENDIAN);
            structRecord.put((byte) 0).putInt(32768).putInt(2).putInt(0);
            structRecord.put((byte) 0).putInt(0x10000010).putInt(32768).putInt(2)
                .putInt(0).putInt(elementRef).putInt(fieldRef).putInt(8192);
            db.put(structs, taggedKey(0x61, structRef), structRecord.array());

            MddbSchema schema = new MddbSchema(db, sp, enums, types, structs);
            assertEquals(
                "TEST_PDU: struct size=32768 align=2 { +0x0 TEST_ELEMENT iq_dump_result[8192] }",
                schema.describeSpMatch(le32(3), offsets.get("TEST_PDU")));
            MddbSchema.ResolvedType type = schema.resolveTypeByName("TEST_PDU");
            assertNotNull(type);
            assertEquals(8192, type.fields().get(0).arrayCount());
        }
    }

    private static byte[] typeAlias(int nextRef) {
        byte[] value = new byte[17];
        ByteBuffer.wrap(value).order(ByteOrder.LITTLE_ENDIAN).putInt(13, nextRef);
        return value;
    }

    private static void putField(ByteBuffer out, int offset, int typeRef, int nameRef) {
        out.put((byte) 0);
        out.putInt(0x10000000);
        out.putInt(2);
        out.putInt(2);
        out.putInt(offset);
        out.putInt(typeRef);
        out.putInt(nameRef);
    }

    private static ColumnFamilyDescriptor cf(String name) {
        return new ColumnFamilyDescriptor(name.getBytes(StandardCharsets.UTF_8));
    }

    private static int packStringRef(int bucket, int offset) {
        return (offset << 14) | bucket;
    }

    private static byte[] taggedKey(int tag, int ref) {
        byte[] key = new byte[5];
        key[0] = (byte) tag;
        System.arraycopy(le32(ref), 0, key, 1, 4);
        return key;
    }

    private static byte[] le32(int value) {
        return ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt(value).array();
    }
}
