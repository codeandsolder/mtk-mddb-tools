package mtk_mddb.ghidra;

import java.io.BufferedWriter;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.function.Consumer;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.util.task.TaskMonitor;

/** Implementation behind the stable TraceMtkProgramStrings Ghidra script wrapper. */
public final class TraceMtkProgramStringsRunner {
    private record Hit(String needle, Address stringAddress, String value,
            Address canonicalReferenceAddress, Address rawReferenceAddress, Function function) {}

    private TraceMtkProgramStringsRunner() {}

    public static void run(Program program, TaskMonitor monitor, Path output, List<String> rawNeedles,
            Consumer<String> log) throws Exception {
        List<String> needles = normalizeNeedles(rawNeedles);
        if (needles.isEmpty()) {
            throw new IllegalArgumentException("Supply at least one non-empty search substring");
        }

        LinkedHashMap<String, Hit> hitsByKey = new LinkedHashMap<>();
        Map<Address, Function> matchedFunctions = new LinkedHashMap<>();
        for (ProgramStringIndex.RawString string : ProgramStringIndex.asciiStrings(program, 4, 2048, monitor)) {
            monitor.checkCancelled();
            String lower = string.value().toLowerCase(Locale.ROOT);
            for (String needle : needles) {
                if (!lower.contains(needle)) {
                    continue;
                }
                boolean referenced = false;
                for (Address target : ProgramComparisonScope.equivalentAddresses(program, string.address())) {
                    ReferenceIterator references = program.getReferenceManager().getReferencesTo(target);
                    while (references.hasNext()) {
                        Reference reference = references.next();
                        Address rawFrom = reference.getFromAddress();
                        Address canonicalFrom = ProgramComparisonScope.canonicalAddress(program, rawFrom);
                        Function function = ProgramComparisonScope.canonicalFunctionContaining(program, rawFrom);
                        Hit hit = new Hit(needle, string.address(), string.value(), canonicalFrom,
                            rawFrom, function);
                        addHit(hitsByKey, hit);
                        if (function != null) {
                            matchedFunctions.put(ProgramComparisonScope.canonicalAddress(
                                program, function.getEntryPoint()), function);
                        }
                        referenced = true;
                    }
                }
                if (!referenced) {
                    addHit(hitsByKey, new Hit(needle, string.address(), string.value(), null, null, null));
                }
            }
        }

        List<Hit> hits = new ArrayList<>(hitsByKey.values());
        hits.sort(Comparator.comparing(Hit::needle)
            .thenComparing(Hit::stringAddress)
            .thenComparing(hit -> hit.canonicalReferenceAddress() == null ?
                hit.stringAddress() : hit.canonicalReferenceAddress()));
        Path parent = output.toAbsolutePath().getParent();
        if (parent != null) {
            Files.createDirectories(parent);
        }
        String scope = ProgramComparisonScope.description(program);
        try (BufferedWriter writer = Files.newBufferedWriter(output)) {
            writer.write("summary\tcomparison_scope\t" + clean(scope) + "\n");
            writer.write("section\tneedle\tstring_address\tstring\txref_address\t" +
                "raw_xref_address\tfunction_address\traw_function_address\tfunction\n");
            for (Hit hit : hits) {
                writer.write(String.join("\t", "string_xref", clean(hit.needle()),
                    hit.stringAddress().toString(), clean(hit.value()),
                    address(hit.canonicalReferenceAddress()), address(hit.rawReferenceAddress()),
                    hit.function() == null ? "" : ProgramComparisonScope.canonicalAddress(
                        program, hit.function().getEntryPoint()).toString(),
                    hit.function() == null ? "" : hit.function().getEntryPoint().toString(),
                    hit.function() == null ? "" : clean(hit.function().getName())));
                writer.write("\n");
            }

            writer.write("\nsection\tfunction_address\tfunction\tdirection\tpeer_address\tpeer\n");
            List<Function> functions = new ArrayList<>(matchedFunctions.values());
            functions.sort(Comparator.comparing(Function::getEntryPoint));
            for (Function function : functions) {
                monitor.checkCancelled();
                writeEdges(writer, function, "caller", function.getCallingFunctions(monitor));
                writeEdges(writer, function, "callee", function.getCalledFunctions(monitor));
            }
        }
        log.accept("MTK_STRING_TRACE=" + output);
        log.accept("MTK_STRING_TRACE_SCOPE=" + scope);
        log.accept("MTK_STRING_TRACE_HITS=" + hits.size());
        log.accept("MTK_STRING_TRACE_FUNCTIONS=" + matchedFunctions.size());
    }

    private static List<String> normalizeNeedles(List<String> values) {
        return values.stream().map(String::trim).filter(value -> !value.isBlank())
            .map(value -> value.toLowerCase(Locale.ROOT)).distinct().toList();
    }

    private static void addHit(Map<String, Hit> hits, Hit hit) {
        String key = hit.needle() + "\u0000" + hit.stringAddress() + "\u0000" +
            address(hit.canonicalReferenceAddress());
        Hit existing = hits.get(key);
        if (existing == null || prefer(hit, existing)) {
            hits.put(key, hit);
        }
    }

    private static boolean prefer(Hit candidate, Hit existing) {
        if (existing.function() == null && candidate.function() != null) {
            return true;
        }
        if (existing.rawReferenceAddress() == null || candidate.rawReferenceAddress() == null) {
            return false;
        }
        // Prefer the already-canonical low reference when both aliases resolve to the same xref.
        return candidate.rawReferenceAddress().equals(candidate.canonicalReferenceAddress()) &&
            !existing.rawReferenceAddress().equals(existing.canonicalReferenceAddress());
    }

    private static void writeEdges(BufferedWriter writer, Function function, String direction,
            Set<Function> peers) throws Exception {
        List<Function> ordered = new ArrayList<>(new LinkedHashSet<>(peers));
        ordered.sort(Comparator.comparing(Function::getEntryPoint));
        for (Function peer : ordered) {
            Address peerAddress = ProgramComparisonScope.canonicalAddress(
                function.getProgram(), peer.getEntryPoint());
            Address functionAddress = ProgramComparisonScope.canonicalAddress(
                function.getProgram(), function.getEntryPoint());
            writer.write(String.join("\t", "call_edge", functionAddress.toString(),
                clean(function.getName()), direction, peerAddress.toString(), clean(peer.getName())));
            writer.write("\n");
        }
    }

    private static String address(Address value) {
        return value == null ? "" : value.toString();
    }

    private static String clean(String value) {
        return value == null ? "" : value.replace("\t", " ").replace("\n", " ").replace("\r", " ");
    }
}
