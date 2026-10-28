package mtk_mddb.ghidra;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.BookmarkType;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

public final class ProgramAnnotator {
    public record AnnotationSummary(int stringMatches, int codeReferences, List<String> functions) {}

    private ProgramAnnotator() {}

    public static List<Address> findAscii(Program program, String text, TaskMonitor monitor)
            throws CancelledException {
        byte[] needle = text.getBytes(StandardCharsets.UTF_8);
        if (needle.length == 0) {
            return List.of();
        }
        Memory memory = program.getMemory();
        List<Address> hits = new ArrayList<>();
        for (var block : ProgramComparisonScope.blocks(program)) {
            Address cursor = block.getStart();
            Address max = block.getEnd();
            while (cursor != null && cursor.compareTo(max) <= 0) {
                monitor.checkCancelled();
                Address hit = memory.findBytes(cursor, max, needle, null, true, monitor);
                if (hit == null) {
                    break;
                }
                hits.add(hit);
                try {
                    cursor = hit.add(1);
                } catch (RuntimeException e) {
                    break;
                }
            }
        }
        return hits;
    }

    public static List<Address> findCodeReferences(Program program, String text, TaskMonitor monitor)
            throws CancelledException {
        LinkedHashSet<Address> refs = new LinkedHashSet<>();
        for (Address hit : findAscii(program, text, monitor)) {
            monitor.checkCancelled();
            for (Address target : ProgramComparisonScope.equivalentAddresses(program, hit)) {
                ReferenceIterator iterator = program.getReferenceManager().getReferencesTo(target);
                while (iterator.hasNext()) {
                    monitor.checkCancelled();
                    Reference ref = iterator.next();
                    Address from = ref.getFromAddress();
                    if (program.getListing().getInstructionContaining(from) != null ||
                            program.getFunctionManager().getFunctionContaining(from) != null) {
                        refs.add(from);
                    }
                }
            }
        }
        return new ArrayList<>(refs);
    }

    public static AnnotationSummary annotate(Program program, String text, TaskMonitor monitor)
            throws CancelledException {
        List<Address> hits = findAscii(program, text, monitor);
        if (hits.isEmpty()) {
            return new AnnotationSummary(0, 0, List.of());
        }
        int tx = program.startTransaction("Annotate MediaTek MDDB matches");
        boolean commit = false;
        LinkedHashSet<Address> codeRefs = new LinkedHashSet<>();
        LinkedHashSet<String> functionNames = new LinkedHashSet<>();
        try {
            SymbolTable symbols = program.getSymbolTable();
            String comment = "MediaTek MDDB: " + text;
            String label = labelFor(text);
            for (Address hit : hits) {
                monitor.checkCancelled();
                program.getBookmarkManager().setBookmark(
                    hit, BookmarkType.ANALYSIS, "MediaTek MDDB", comment);
                appendComment(program, hit, comment);
                if (label != null && symbols.getPrimarySymbol(hit) == null) {
                    try {
                        symbols.createLabel(hit, label, SourceType.ANALYSIS);
                    } catch (InvalidInputException ignored) {
                        // Comments/bookmarks remain useful if the text is not a valid symbol name.
                    }
                }

                for (Address target : ProgramComparisonScope.equivalentAddresses(program, hit)) {
                    ReferenceIterator iterator = program.getReferenceManager().getReferencesTo(target);
                    while (iterator.hasNext()) {
                        monitor.checkCancelled();
                        Reference ref = iterator.next();
                        Address from = ref.getFromAddress();
                        if (program.getListing().getInstructionContaining(from) == null &&
                                program.getFunctionManager().getFunctionContaining(from) == null) {
                            continue;
                        }
                        if (codeRefs.add(from)) {
                            String xrefComment = "MediaTek MDDB xref: " + text;
                            program.getBookmarkManager().setBookmark(
                                from, BookmarkType.ANALYSIS, "MediaTek MDDB xref", xrefComment);
                            appendComment(program, from, xrefComment);
                        }
                        Function function = program.getFunctionManager().getFunctionContaining(from);
                        if (function != null) {
                            functionNames.add(function.getName() + " @ " + function.getEntryPoint());
                        }
                    }
                }
            }
            commit = true;
            return new AnnotationSummary(hits.size(), codeRefs.size(), new ArrayList<>(functionNames));
        } finally {
            program.endTransaction(tx, commit);
        }
    }

    private static void appendComment(Program program, Address address, String line) {
        String existing = program.getListing().getComment(CommentType.PRE, address);
        if (existing == null || existing.isBlank()) {
            program.getListing().setComment(address, CommentType.PRE, line);
        } else if (!existing.contains(line)) {
            program.getListing().setComment(address, CommentType.PRE, existing + "\n" + line);
        }
    }

    private static String labelFor(String text) {
        if (!text.matches("[A-Za-z_][A-Za-z0-9_]{2,127}")) {
            return null;
        }
        return "mddb_" + text;
    }
}
