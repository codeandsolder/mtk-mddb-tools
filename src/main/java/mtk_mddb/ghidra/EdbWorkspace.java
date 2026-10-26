package mtk_mddb.ghidra;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

import org.tukaani.xz.LZMAInputStream;

final class EdbWorkspace implements AutoCloseable {
    private record Section(String name, int offset, int compressedSize, int uncompressedSize) {}
    private record PackedFile(String name, byte[] payload) {}

    private final Path root;
    private final Path tempRoot;
    private final byte[] dataA;

    private EdbWorkspace(Path root, Path tempRoot, byte[] dataA) {
        this.root = root;
        this.tempRoot = tempRoot;
        this.dataA = dataA;
    }

    static EdbWorkspace open(Path source) throws IOException {
        if (Files.isDirectory(source)) {
            return fromExtractedDirectory(source);
        }
        byte[] blob = Files.readAllBytes(source);
        List<Section> sections = parseSections(blob);
        byte[] dataI = null;
        byte[] dataA = null;
        for (Section section : sections) {
            byte[] decoded = decompress(blob, section);
            if (section.name().equals("DATAI")) {
                dataI = decoded;
            } else if (section.name().equals("DATAA")) {
                dataA = decoded;
            }
        }
        if (dataI == null || dataA == null) {
            throw new IOException("CATD database is missing DATAI or DATAA");
        }

        Path temp = Files.createTempDirectory("mtk-mddb-ghidra-");
        try {
            java.util.HashSet<Path> outputs = new java.util.HashSet<>();
            for (PackedFile file : parseDataI(dataI)) {
                Path out = safeResolve(temp, file.name());
                if (!outputs.add(out)) {
                    throw new IOException("Duplicate DATAI output path: " + file.name());
                }
                Files.createDirectories(out.getParent());
                Files.write(out, file.payload());
            }
            makeRocksDbCompatible(temp);
            return new EdbWorkspace(temp, temp, dataA);
        } catch (IOException | RuntimeException e) {
            deleteTree(temp);
            throw e;
        }
    }

    private static EdbWorkspace fromExtractedDirectory(Path source) throws IOException {
        Path rocks = Files.isDirectory(source.resolve("rocksdb")) ? source.resolve("rocksdb") : source;
        if (!Files.isRegularFile(rocks.resolve("CURRENT"))) {
            throw new IOException("Directory does not contain an extracted RocksDB: " + rocks);
        }
        Path temp = Files.createTempDirectory("mtk-mddb-ghidra-view-");
        try {
            try (var entries = Files.list(rocks)) {
                for (Path entry : entries.toList()) {
                    if (Files.isRegularFile(entry)) {
                        Files.copy(entry, temp.resolve(entry.getFileName()), StandardCopyOption.REPLACE_EXISTING);
                    }
                }
            }
            Path sp = rocks.resolve("sp");
            if (Files.isDirectory(sp)) {
                try (var entries = Files.list(sp)) {
                    for (Path entry : entries.toList()) {
                        if (Files.isRegularFile(entry) && entry.getFileName().toString().endsWith(".sst")) {
                            Files.copy(entry, temp.resolve(entry.getFileName()), StandardCopyOption.REPLACE_EXISTING);
                        }
                    }
                }
            }
            Files.createDirectories(temp.resolve("db"));
            Path dataAPath = Files.isDirectory(source.resolve("rocksdb"))
                ? source.resolve("DATAA.bin")
                : source.getParent() == null ? source.resolve("DATAA.bin") : source.getParent().resolve("DATAA.bin");
            byte[] dataA = Files.isRegularFile(dataAPath) ? Files.readAllBytes(dataAPath) : new byte[0];
            return new EdbWorkspace(temp, temp, dataA);
        } catch (IOException | RuntimeException e) {
            deleteTree(temp);
            throw e;
        }
    }

    Path rocksDbRoot() {
        return root;
    }

    byte[] dataA() {
        return dataA.clone();
    }

    int dataASize() {
        return dataA.length;
    }

    private static List<Section> parseSections(byte[] blob) throws IOException {
        if (blob.length < 4 || Byte.toUnsignedInt(blob[0]) != 0x43 || Byte.toUnsignedInt(blob[1]) != 0x41 || Byte.toUnsignedInt(blob[2]) != 0x54 || Byte.toUnsignedInt(blob[3]) != 0x44) {
            throw new IOException("Not a MediaTek CATD EDB file");
        }
        List<Section> sections = new ArrayList<>();
        for (String name : List.of("DATAI", "DATAA")) {
            byte[] tag = (name + "\0\0\0").getBytes(StandardCharsets.US_ASCII);
            int at = indexOf(blob, tag, 0, Math.min(blob.length, 4096));
            if (at < 0 || at + 20 > blob.length) {
                throw new IOException("Missing " + name + " descriptor");
            }
            int offset = u32(blob, at + 8);
            int compressed = u32(blob, at + 12);
            int uncompressed = u32(blob, at + 16);
            long end = Integer.toUnsignedLong(offset) + Integer.toUnsignedLong(compressed);
            if (compressed <= 5 || uncompressed <= 0 || offset < 0 || end > blob.length) {
                throw new IOException("Invalid " + name + " bounds");
            }
            sections.add(new Section(name, offset, compressed, uncompressed));
        }
        sections.sort(Comparator.comparingInt(Section::offset));
        for (int i = 1; i < sections.size(); i++) {
            Section prev = sections.get(i - 1);
            Section next = sections.get(i);
            if ((long) prev.offset() + prev.compressedSize() > next.offset()) {
                throw new IOException("Overlapping CATD sections");
            }
        }
        return sections;
    }

    private static byte[] decompress(byte[] blob, Section section) throws IOException {
        int at = section.offset();
        int prop = Byte.toUnsignedInt(blob[at]);
        if (prop >= 9 * 5 * 5) {
            throw new IOException(section.name() + ": invalid LZMA properties");
        }
        int dictSize = u32(blob, at + 1);
        int payloadStart = at + 5;
        int payloadLength = section.compressedSize() - 5;
        try (InputStream raw = new ByteArrayInputStream(blob, payloadStart, payloadLength);
             LZMAInputStream lzma = new LZMAInputStream(raw, -1, (byte) prop, dictSize);
             ByteArrayOutputStream out = new ByteArrayOutputStream(section.uncompressedSize())) {
            lzma.enableRelaxedEndCondition();
            lzma.transferTo(out);
            byte[] decoded = out.toByteArray();
            if (decoded.length != section.uncompressedSize()) {
                throw new IOException(section.name() + ": decoded " + decoded.length + " bytes, expected " + section.uncompressedSize());
            }
            return decoded;
        }
    }

    private static List<PackedFile> parseDataI(byte[] data) throws IOException {
        List<PackedFile> files = new ArrayList<>();
        int pos = 0;
        while (pos < data.length) {
            if (pos + 8 > data.length) {
                throw new IOException("DATAI truncated at 0x" + Integer.toHexString(pos));
            }
            long span = u64(data, pos);
            int nameStart = pos + 8;
            int nameEnd = indexOfByte(data, (byte) 0, nameStart, Math.min(data.length, nameStart + 4096));
            if (nameEnd < 0) {
                throw new IOException("DATAI filename is not NUL terminated");
            }
            String name = new String(data, nameStart, nameEnd - nameStart, StandardCharsets.UTF_8);
            if (name.isBlank() || name.startsWith("/") || name.contains("../") || name.contains("\\")) {
                throw new IOException("Unsafe DATAI filename: " + name);
            }
            long nextNameStartLong = nameStart + span;
            long payloadEndLong = nextNameStartLong - 8;
            int payloadStart = nameEnd + 1;
            if (payloadEndLong < payloadStart || payloadEndLong > data.length || nextNameStartLong > Integer.MAX_VALUE) {
                throw new IOException("Invalid DATAI span for " + name);
            }
            int payloadEnd = (int) payloadEndLong;
            byte[] payload = java.util.Arrays.copyOfRange(data, payloadStart, payloadEnd);
            files.add(new PackedFile(name, payload));
            pos = payloadEnd;
        }
        return files;
    }

    private static void makeRocksDbCompatible(Path root) throws IOException {
        Path sp = root.resolve("sp");
        if (Files.isDirectory(sp)) {
            try (var entries = Files.list(sp)) {
                for (Path entry : entries.toList()) {
                    if (!Files.isRegularFile(entry) || !entry.getFileName().toString().endsWith(".sst")) {
                        continue;
                    }
                    Path flat = root.resolve(entry.getFileName());
                    if (!Files.exists(flat)) {
                        try {
                            Files.createLink(flat, entry);
                        } catch (IOException e) {
                            Files.copy(entry, flat, StandardCopyOption.REPLACE_EXISTING);
                        }
                    }
                }
            }
        }
        Files.createDirectories(root.resolve("db"));
    }

    private static Path safeResolve(Path root, String name) throws IOException {
        Path resolved = root.resolve(name).normalize();
        if (!resolved.startsWith(root)) {
            throw new IOException("DATAI path escapes extraction root: " + name);
        }
        return resolved;
    }

    private static int u32(byte[] data, int offset) {
        return ByteBuffer.wrap(data, offset, 4).order(ByteOrder.LITTLE_ENDIAN).getInt();
    }

    private static long u64(byte[] data, int offset) {
        return ByteBuffer.wrap(data, offset, 8).order(ByteOrder.LITTLE_ENDIAN).getLong();
    }

    private static int indexOf(byte[] haystack, byte[] needle, int start, int end) {
        outer: for (int i = start; i <= end - needle.length; i++) {
            for (int j = 0; j < needle.length; j++) {
                if (haystack[i + j] != needle[j]) {
                    continue outer;
                }
            }
            return i;
        }
        return -1;
    }

    private static int indexOfByte(byte[] data, byte needle, int start, int end) {
        for (int i = start; i < end; i++) {
            if (data[i] == needle) {
                return i;
            }
        }
        return -1;
    }

    private static void deleteTree(Path root) throws IOException {
        if (root == null || !Files.exists(root)) {
            return;
        }
        try (var stream = Files.walk(root)) {
            for (Path path : stream.sorted(Comparator.reverseOrder()).toList()) {
                Files.deleteIfExists(path);
            }
        }
    }

    @Override
    public void close() throws IOException {
        deleteTree(tempRoot);
    }
}
