package mtk_mddb.ghidra;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/** Single-pass inventory of null-terminated printable ASCII strings in loaded program memory. */
public final class ProgramStringIndex {
    private static final int CHUNK_BYTES = 1 << 20;
    private static final long MAX_MATCHING_RUN_GAP_BYTES = 4096;

    public record RawString(Address address, String value) {}

    public record MatchingRun(Address sourceStart, Address sourceEnd, Address targetStart,
            Address targetEnd, int strings, long addressDelta, String firstValue,
            String lastValue) {}

    private ProgramStringIndex() {}

    public static List<RawString> asciiStrings(Program program, int minimumLength,
            int maximumLength, TaskMonitor monitor) throws CancelledException, MemoryAccessException {
        if (minimumLength < 1 || maximumLength < minimumLength) {
            throw new IllegalArgumentException("Invalid ASCII string length range");
        }
        Memory memory = program.getMemory();
        List<RawString> out = new ArrayList<>();
        byte[] buffer = new byte[CHUNK_BYTES];

        for (MemoryBlock block : ProgramComparisonScope.blocks(program)) {
            monitor.checkCancelled();
            if (!block.isInitialized() || !block.isLoaded()) {
                continue;
            }
            StringBuilder current = new StringBuilder(Math.min(maximumLength, 256));
            Address stringStart = null;
            boolean tooLong = false;
            long offset = 0;
            while (offset < block.getSize()) {
                monitor.checkCancelled();
                int request = (int) Math.min(buffer.length, block.getSize() - offset);
                Address chunkStart = block.getStart().add(offset);
                int read = memory.getBytes(chunkStart, buffer, 0, request);
                if (read <= 0) {
                    break;
                }
                for (int i = 0; i < read; i++) {
                    int value = Byte.toUnsignedInt(buffer[i]);
                    if (isPrintableAscii(value)) {
                        if (current.isEmpty() && !tooLong) {
                            stringStart = chunkStart.add(i);
                        }
                        if (!tooLong) {
                            if (current.length() < maximumLength) {
                                current.append((char) value);
                            } else {
                                current.setLength(0);
                                stringStart = null;
                                tooLong = true;
                            }
                        }
                        continue;
                    }

                    if (value == 0 && !tooLong && stringStart != null &&
                            current.length() >= minimumLength) {
                        out.add(new RawString(stringStart, current.toString()));
                    }
                    current.setLength(0);
                    stringStart = null;
                    tooLong = false;
                }
                offset += read;
            }
        }
        out.sort(Comparator.comparing(RawString::address));
        return List.copyOf(out);
    }

    public static List<MatchingRun> matchingRuns(List<RawString> source, List<RawString> target,
            int minimumStrings) {
        if (minimumStrings < 2) {
            throw new IllegalArgumentException("minimumStrings must be at least 2");
        }
        Map<String, List<Integer>> targetIndices = new HashMap<>();
        for (int i = 0; i < target.size(); i++) {
            targetIndices.computeIfAbsent(target.get(i).value(), ignored -> new ArrayList<>()).add(i);
        }

        boolean[] covered = new boolean[source.size()];
        List<MatchingRun> runs = new ArrayList<>();
        Map<String, MatchingRun> deduplicated = new HashMap<>();
        for (int sourceIndex = 0; sourceIndex < source.size(); sourceIndex++) {
            if (covered[sourceIndex]) {
                continue;
            }
            List<Integer> candidates = targetIndices.get(source.get(sourceIndex).value());
            if (candidates == null || candidates.size() > 32) {
                continue;
            }
            MatchingRun best = null;
            int bestSourceLeft = -1;
            int bestSourceRight = -1;
            for (int targetIndex : candidates) {
                long delta = target.get(targetIndex).address().subtract(source.get(sourceIndex).address());
                int sourceLeft = sourceIndex;
                int targetLeft = targetIndex;
                while (sourceLeft > 0 && targetLeft > 0 &&
                        nearby(source.get(sourceLeft - 1), source.get(sourceLeft)) &&
                        sameAtDelta(source.get(sourceLeft - 1), target.get(targetLeft - 1), delta)) {
                    sourceLeft--;
                    targetLeft--;
                }
                int sourceRight = sourceIndex;
                int targetRight = targetIndex;
                while (sourceRight + 1 < source.size() && targetRight + 1 < target.size() &&
                        nearby(source.get(sourceRight), source.get(sourceRight + 1)) &&
                        sameAtDelta(source.get(sourceRight + 1), target.get(targetRight + 1), delta)) {
                    sourceRight++;
                    targetRight++;
                }
                int length = sourceRight - sourceLeft + 1;
                if (length < minimumStrings) {
                    continue;
                }
                if (best != null && (length < best.strings() ||
                        (length == best.strings() &&
                            displacementMagnitude(delta) >=
                                displacementMagnitude(best.addressDelta())))) {
                    continue;
                }
                best = new MatchingRun(source.get(sourceLeft).address(),
                    source.get(sourceRight).address(), target.get(targetLeft).address(),
                    target.get(targetRight).address(), length, delta, source.get(sourceLeft).value(),
                    source.get(sourceRight).value());
                bestSourceLeft = sourceLeft;
                bestSourceRight = sourceRight;
            }
            if (best == null) {
                continue;
            }
            for (int i = bestSourceLeft; i <= bestSourceRight; i++) {
                covered[i] = true;
            }
            String key = best.strings() + "\u0000" + best.addressDelta() + "\u0000" +
                best.firstValue() + "\u0000" + best.lastValue();
            MatchingRun existing = deduplicated.get(key);
            if (existing == null || best.sourceStart().compareTo(existing.sourceStart()) < 0) {
                deduplicated.put(key, best);
            }
        }
        runs.addAll(deduplicated.values());
        runs.sort(Comparator.comparingInt(MatchingRun::strings).reversed()
            .thenComparing(MatchingRun::sourceStart));
        return List.copyOf(runs);
    }

    private static boolean sameAtDelta(RawString source, RawString target, long delta) {
        return source.value().equals(target.value()) &&
            target.address().subtract(source.address()) == delta;
    }

    private static boolean nearby(RawString first, RawString second) {
        long gap = second.address().subtract(first.address());
        return gap >= 0 && gap <= MAX_MATCHING_RUN_GAP_BYTES;
    }

    private static long displacementMagnitude(long value) {
        return value == Long.MIN_VALUE ? Long.MAX_VALUE : Math.abs(value);
    }

    private static boolean isPrintableAscii(int value) {
        return value >= 0x20 && value <= 0x7e;
    }
}
