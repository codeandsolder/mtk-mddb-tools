package mtk_mddb.ghidra;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.tukaani.xz.LZMA2Options;
import org.tukaani.xz.LZMAOutputStream;

class EdbWorkspaceTest {
    @TempDir
    Path tempDir;

    @Test
    void opensSyntheticCatdAndPackedDataI() throws Exception {
        byte[] current = "MANIFEST-000001\n".getBytes(StandardCharsets.US_ASCII);
        byte[] dataI = packedFile("CURRENT", current);
        byte[] dataA = "trace metadata".getBytes(StandardCharsets.US_ASCII);
        byte[] encodedI = rawLzma(dataI);
        byte[] encodedA = rawLzma(dataA);

        int dataIOffset = 94;
        int dataAOffset = dataIOffset + encodedI.length;
        byte[] edb = new byte[dataAOffset + encodedA.length];
        System.arraycopy("CATD".getBytes(StandardCharsets.US_ASCII), 0, edb, 0, 4);
        descriptor(edb, 48, "DATAI", dataIOffset, encodedI.length, dataI.length);
        descriptor(edb, 74, "DATAA", dataAOffset, encodedA.length, dataA.length);
        System.arraycopy(encodedI, 0, edb, dataIOffset, encodedI.length);
        System.arraycopy(encodedA, 0, edb, dataAOffset, encodedA.length);

        Path input = tempDir.resolve("synthetic.EDB");
        Files.write(input, edb);
        try (EdbWorkspace workspace = EdbWorkspace.open(input)) {
            assertArrayEquals(current, Files.readAllBytes(workspace.rocksDbRoot().resolve("CURRENT")));
            assertArrayEquals(dataA, workspace.dataA());
            assertTrue(Files.isDirectory(workspace.rocksDbRoot().resolve("db")));
        }
    }

    private static byte[] packedFile(String name, byte[] payload) {
        byte[] encodedName = name.getBytes(StandardCharsets.UTF_8);
        int total = 8 + encodedName.length + 1 + payload.length;
        ByteBuffer out = ByteBuffer.allocate(total).order(ByteOrder.LITTLE_ENDIAN);
        out.putLong(total);
        out.put(encodedName).put((byte) 0).put(payload);
        return out.array();
    }

    private static byte[] rawLzma(byte[] data) throws Exception {
        LZMA2Options options = new LZMA2Options();
        options.setDictSize(1 << 20);
        ByteArrayOutputStream compressed = new ByteArrayOutputStream();
        int props;
        try (LZMAOutputStream lzma = new LZMAOutputStream(compressed, options, true)) {
            props = lzma.getProps();
            lzma.write(data);
        }
        ByteBuffer out = ByteBuffer.allocate(5 + compressed.size()).order(ByteOrder.LITTLE_ENDIAN);
        out.put((byte) props).putInt(options.getDictSize()).put(compressed.toByteArray());
        return out.array();
    }

    private static void descriptor(byte[] out, int at, String name, int offset, int compressed, int uncompressed) {
        byte[] tag = (name + "\0\0\0").getBytes(StandardCharsets.US_ASCII);
        System.arraycopy(tag, 0, out, at, tag.length);
        ByteBuffer.wrap(out, at + 8, 12).order(ByteOrder.LITTLE_ENDIAN)
            .putInt(offset).putInt(compressed).putInt(uncompressed);
    }
}
