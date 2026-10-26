package mtk_mddb.ghidra;

public record MddbSearchResult(String columnFamily, String field, byte[] key, int offset, byte[] value) {
    public String keyHex() {
        return java.util.HexFormat.of().formatHex(key);
    }
}
