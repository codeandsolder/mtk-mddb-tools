package mtk_mddb.ghidra;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.List;

import org.junit.jupiter.api.Test;

import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.address.GenericAddressSpace;

class ProgramStringIndexTest {
    private static final GenericAddressSpace SPACE =
        new GenericAddressSpace("ram", 32, 1, AddressSpace.TYPE_RAM);

    @Test
    void matchesAndDeduplicatesMirroredConstantDeltaRuns() {
        List<ProgramStringIndex.RawString> source = List.of(
            raw(0x100, "ALPHA"), raw(0x108, "BETA"), raw(0x110, "GAMMA"),
            raw(0x90000100L, "ALPHA"), raw(0x90000108L, "BETA"),
            raw(0x90000110L, "GAMMA"));
        List<ProgramStringIndex.RawString> target = List.of(
            raw(0x170, "ALPHA"), raw(0x178, "BETA"), raw(0x180, "GAMMA"),
            raw(0x90000170L, "ALPHA"), raw(0x90000178L, "BETA"),
            raw(0x90000180L, "GAMMA"));

        List<ProgramStringIndex.MatchingRun> runs =
            ProgramStringIndex.matchingRuns(source, target, 3);

        assertEquals(1, runs.size());
        ProgramStringIndex.MatchingRun run = runs.get(0);
        assertEquals(3, run.strings());
        assertEquals(0x70, run.addressDelta());
        assertEquals(0x100, run.sourceStart().getOffset());
        assertEquals(0x170, run.targetStart().getOffset());
        assertEquals("ALPHA", run.firstValue());
        assertEquals("GAMMA", run.lastValue());
    }

    private static ProgramStringIndex.RawString raw(long address, String value) {
        return new ProgramStringIndex.RawString(SPACE.getAddress(address), value);
    }
}
