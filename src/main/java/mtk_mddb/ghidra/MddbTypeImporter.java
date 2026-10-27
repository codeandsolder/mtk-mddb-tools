package mtk_mddb.ghidra;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.rocksdb.RocksDBException;

import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.BooleanDataType;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.CharDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.EnumDataType;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.data.LongLongDataType;
import ghidra.program.model.data.ShortDataType;
import ghidra.program.model.data.SignedByteDataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.Undefined;
import ghidra.program.model.data.UnionDataType;
import ghidra.program.model.data.UnsignedIntegerDataType;
import ghidra.program.model.data.UnsignedLongLongDataType;
import ghidra.program.model.data.UnsignedShortDataType;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;

/** Materializes decoded MDDB schemas in a program data-type manager. */
public final class MddbTypeImporter {
    private static final CategoryPath CATEGORY = new CategoryPath("/MediaTek MDDB");
    private static final int MAX_TYPE_SIZE = 64 * 1024 * 1024;

    /** Paths of top-level data types imported for the selected MDDB result. */
    public record ImportSummary(List<String> imported) {}

    private final Program program;
    private final MddbDatabase database;
    private final DataTypeManager manager;
    private final TaskMonitor monitor;
    private final Map<String, DataType> importedByName = new HashMap<>();
    private final Set<String> resolving = new HashSet<>();

    private MddbTypeImporter(Program program, MddbDatabase database, TaskMonitor monitor) {
        this.program = program;
        this.database = database;
        this.manager = program.getDataTypeManager();
        this.monitor = monitor;
    }

    /** Imports the decoded type and/or enum associated with one MDDB search result. */
    public static ImportSummary importSelection(Program program, MddbDatabase database,
            MddbSearchResult result, TaskMonitor monitor) throws Exception {
        return new MddbTypeImporter(program, database, monitor).run(result);
    }

    private ImportSummary run(MddbSearchResult result) throws Exception {
        MddbSchema.ResolvedType type = database.resolvedType(result);
        List<MddbSchema.EnumDefinition> enums = database.enumDefinitions(result);
        if (type == null && enums.isEmpty()) {
            return new ImportSummary(List.of());
        }

        LinkedHashSet<String> names = new LinkedHashSet<>();
        int tx = program.startTransaction("Import MediaTek MDDB data types");
        boolean commit = false;
        try {
            if (type != null) {
                DataType imported = importResolvedType(type);
                if (imported != null) {
                    names.add(imported.getPathName());
                }
            }
            for (MddbSchema.EnumDefinition definition : enums) {
                monitor.checkCancelled();
                DataType imported = importEnum(definition);
                names.add(imported.getPathName());
            }
            commit = true;
        } finally {
            program.endTransaction(tx, commit);
        }
        return new ImportSummary(List.copyOf(names));
    }

    private DataType importResolvedType(MddbSchema.ResolvedType definition) throws Exception {
        DataType cached = importedByName.get(definition.name());
        if (cached != null) {
            return cached;
        }
        if (!resolving.add(definition.name())) {
            return null;
        }
        try {
            monitor.checkCancelled();
            int size = checkedSize(definition.size(), definition.name());
            DataType composite = definition.kind().equals("union")
                ? buildUnion(definition)
                : buildStructure(definition, size);
            DataType resolved = manager.addDataType(composite, DataTypeConflictHandler.REPLACE_HANDLER);
            importedByName.put(definition.name(), resolved);
            return resolved;
        } finally {
            resolving.remove(definition.name());
        }
    }

    private DataType buildStructure(MddbSchema.ResolvedType definition, int size) throws Exception {
        StructureDataType structure = new StructureDataType(CATEGORY, definition.name(), size, manager);
        List<MddbSchema.StructField> fields = sortedFields(definition.fields());
        for (int i = 0; i < fields.size(); i++) {
            monitor.checkCancelled();
            MddbSchema.StructField field = fields.get(i);
            int offset = checkedOffset(field.offset(), size, field.fieldName());
            int end = i + 1 < fields.size()
                ? checkedOffset(fields.get(i + 1).offset(), size, fields.get(i + 1).fieldName())
                : size;
            int span = Math.max(0, end - offset);
            if (span == 0) {
                continue;
            }
            DataType fieldType = resolveFieldType(field, span);
            int length = Math.min(span, Math.max(1, fieldType.getLength()));
            structure.replaceAtOffset(offset, fieldType, length, field.fieldName(),
                "MediaTek MDDB");
        }
        return structure;
    }

    private DataType buildUnion(MddbSchema.ResolvedType definition) throws Exception {
        UnionDataType union = new UnionDataType(CATEGORY, definition.name(), manager);
        int size = checkedSize(definition.size(), definition.name());
        for (MddbSchema.StructField field : sortedFields(definition.fields())) {
            monitor.checkCancelled();
            DataType fieldType = resolveFieldType(field, size);
            union.add(fieldType, Math.max(1, fieldType.getLength()), field.fieldName(),
                "MediaTek MDDB");
        }
        if (union.getLength() < size) {
            union.add(Undefined.getUndefinedDataType(size), size, "_mddb_size", "declared MDDB size");
        }
        return union;
    }

    private DataType resolveFieldType(MddbSchema.StructField field, int span) throws Exception {
        DataType base = primitive(field.typeName());
        if (base == null) {
            MddbSchema.ResolvedType nested = database.resolvedTypeByName(field.typeName());
            if (nested != null) {
                base = importResolvedType(nested);
            } else {
                MddbSchema.EnumDefinition nestedEnum = database.resolvedEnumByName(field.typeName());
                if (nestedEnum != null) {
                    base = importEnum(nestedEnum);
                }
            }
        }
        if (field.arrayCount() > 0) {
            int count = checkedCount(field.arrayCount(), field.fieldName());
            int elementLength = span / count;
            if (span % count == 0 && elementLength > 0) {
                if (base == null || base.getLength() != elementLength) {
                    base = Undefined.getUndefinedDataType(elementLength);
                }
                return new ArrayDataType(base, count, elementLength, manager);
            }
        }
        if (base != null && base.getLength() > 0 && base.getLength() <= span) {
            return base;
        }
        return Undefined.getUndefinedDataType(span);
    }

    private DataType importEnum(MddbSchema.EnumDefinition definition) {
        int size = definition.size();
        if (size != 1 && size != 2 && size != 4 && size != 8) {
            size = 4;
        }
        EnumDataType enumType = new EnumDataType(CATEGORY, definition.name(), size, manager);
        for (MddbSchema.EnumValue value : definition.values()) {
            if (!enumType.contains(value.name())) {
                enumType.add(value.name(), value.value());
            }
        }
        return manager.addDataType(enumType, DataTypeConflictHandler.REPLACE_HANDLER);
    }

    private static List<MddbSchema.StructField> sortedFields(List<MddbSchema.StructField> fields) {
        List<MddbSchema.StructField> sorted = new ArrayList<>(fields);
        sorted.sort(Comparator.comparingLong(MddbSchema.StructField::offset));
        return sorted;
    }

    private static DataType primitive(String name) {
        return switch (name) {
            case "kal_bool", "bool", "boolean" -> BooleanDataType.dataType;
            case "kal_int8", "int8", "int8_t", "signed_char" -> SignedByteDataType.dataType;
            case "kal_uint8", "uint8", "uint8_t", "unsigned_char", "U8" -> ByteDataType.dataType;
            case "kal_int16", "int16", "int16_t" -> ShortDataType.dataType;
            case "kal_uint16", "uint16", "uint16_t", "U16" -> UnsignedShortDataType.dataType;
            case "kal_int32", "int32", "int32_t" -> IntegerDataType.dataType;
            case "kal_uint32", "uint32", "uint32_t", "U32" -> UnsignedIntegerDataType.dataType;
            case "kal_int64", "int64", "int64_t" -> LongLongDataType.dataType;
            case "kal_uint64", "uint64", "uint64_t", "U64" -> UnsignedLongLongDataType.dataType;
            case "kal_char", "char" -> CharDataType.dataType;
            default -> null;
        };
    }

    private static int checkedSize(long size, String name) {
        if (size <= 0 || size > MAX_TYPE_SIZE) {
            throw new IllegalArgumentException("Unsupported MDDB type size for " + name + ": " + size);
        }
        return (int) size;
    }

    private static int checkedOffset(long offset, int size, String fieldName) {
        if (offset < 0 || offset > size) {
            throw new IllegalArgumentException("Invalid MDDB field offset for " + fieldName + ": " + offset);
        }
        return (int) offset;
    }

    private static int checkedCount(long count, String fieldName) {
        if (count <= 0 || count > Integer.MAX_VALUE) {
            throw new IllegalArgumentException("Invalid MDDB array count for " + fieldName + ": " + count);
        }
        return (int) count;
    }
}
