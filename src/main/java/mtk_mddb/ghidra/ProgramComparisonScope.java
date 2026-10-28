package mtk_mddb.ghidra;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;

/** Chooses a deduplicated logical address view for MediaTek cross-build analysis. */
public final class ProgramComparisonScope {
    private static final long MTK_RUNTIME_ALIAS = 0x90000000L;

    private ProgramComparisonScope() {}

    /**
     * Blocks used for raw strings and VT. NCC's loader imports md1rom twice; the low mirror owns
     * the entry point and imported debug symbols, so the duplicate runtime main block is excluded.
     * Any additional initialized blocks remain in scope.
     */
    public static List<MemoryBlock> blocks(Program program) {
        Memory memory = program.getMemory();
        MemoryBlock mirror = memory.getBlock("mirror");
        MemoryBlock main = memory.getBlock("main");
        List<MemoryBlock> loaded = loadedInitializedBlocks(memory);
        if (!isNccMtkAliasPair(mirror, main)) {
            return loaded;
        }
        List<MemoryBlock> out = new ArrayList<>(loaded.size() - 1);
        for (MemoryBlock block : loaded) {
            if (block != main) {
                out.add(block);
            }
        }
        return List.copyOf(out);
    }

    public static AddressSetView addressSet(Program program) {
        AddressSet out = new AddressSet();
        for (MemoryBlock block : blocks(program)) {
            out.add(block.getStart(), block.getEnd());
        }
        return out;
    }

    public static boolean contains(Program program, Address address) {
        for (MemoryBlock block : blocks(program)) {
            if (block.contains(address)) {
                return true;
            }
        }
        return false;
    }

    /** Return the canonical low-mirror address for an address in either NCC loader alias. */
    public static Address canonicalAddress(Program program, Address address) {
        Memory memory = program.getMemory();
        MemoryBlock mirror = memory.getBlock("mirror");
        MemoryBlock main = memory.getBlock("main");
        if (!isNccMtkAliasPair(mirror, main) || !main.contains(address)) {
            return address;
        }
        long offset = address.subtract(main.getStart());
        return mirror.getStart().add(offset);
    }

    /**
     * Return every equivalent address worth checking for references, canonical address first.
     * Non-NCC programs simply return the supplied address.
     */
    public static List<Address> equivalentAddresses(Program program, Address address) {
        Memory memory = program.getMemory();
        MemoryBlock mirror = memory.getBlock("mirror");
        MemoryBlock main = memory.getBlock("main");
        if (!isNccMtkAliasPair(mirror, main)) {
            return List.of(address);
        }
        if (mirror.contains(address)) {
            long offset = address.subtract(mirror.getStart());
            return List.of(address, main.getStart().add(offset));
        }
        if (main.contains(address)) {
            long offset = address.subtract(main.getStart());
            Address canonical = mirror.getStart().add(offset);
            return List.of(canonical, address);
        }
        return List.of(address);
    }

    /**
     * Return one representative per logical function entry. Prefer the low/symbolized function
     * when both aliases were analyzed, but keep runtime-only functions instead of discarding them.
     */
    public static List<Function> functions(Program program) {
        Map<Address, Function> byCanonicalEntry = new LinkedHashMap<>();
        var iterator = program.getFunctionManager().getFunctions(true);
        while (iterator.hasNext()) {
            Function function = iterator.next();
            Address entry = function.getEntryPoint();
            MemoryBlock block = program.getMemory().getBlock(entry);
            if (block == null || !block.isLoaded() || !block.isInitialized()) {
                continue;
            }
            Address canonical = canonicalAddress(program, entry);
            Function existing = byCanonicalEntry.get(canonical);
            if (existing == null || prefer(function, existing, canonical)) {
                byCanonicalEntry.put(canonical, function);
            }
        }
        List<Map.Entry<Address, Function>> ordered = new ArrayList<>(byCanonicalEntry.entrySet());
        ordered.sort(Map.Entry.comparingByKey(Comparator.naturalOrder()));
        return ordered.stream().map(Map.Entry::getValue).toList();
    }

    /** Find the best representative function containing either alias address. */
    public static Function canonicalFunctionContaining(Program program, Address address) {
        Address canonical = canonicalAddress(program, address);
        Function low = program.getFunctionManager().getFunctionContaining(canonical);
        Function alias = null;
        for (Address candidate : equivalentAddresses(program, canonical)) {
            if (candidate.equals(canonical)) {
                continue;
            }
            alias = program.getFunctionManager().getFunctionContaining(candidate);
            if (alias != null) {
                break;
            }
        }
        if (low == null) {
            return alias;
        }
        if (alias == null) {
            return low;
        }
        if (low.isThunk() != alias.isThunk()) {
            return low.isThunk() ? alias : low;
        }
        return low;
    }

    public static String description(Program program) {
        Memory memory = program.getMemory();
        if (isNccMtkAliasPair(memory.getBlock("mirror"), memory.getBlock("main"))) {
            return "NCC MediaTek deduplicated mirror/main function view + canonical strings";
        }
        return blocks(program).size() + " loaded initialized block(s)";
    }

    private static boolean prefer(Function candidate, Function existing, Address canonical) {
        if (candidate.isThunk() != existing.isThunk()) {
            return !candidate.isThunk();
        }
        boolean candidateCanonical = candidate.getEntryPoint().equals(canonical);
        boolean existingCanonical = existing.getEntryPoint().equals(canonical);
        if (candidateCanonical != existingCanonical) {
            return candidateCanonical;
        }
        return false;
    }

    private static List<MemoryBlock> loadedInitializedBlocks(Memory memory) {
        List<MemoryBlock> out = new ArrayList<>();
        for (MemoryBlock block : memory.getBlocks()) {
            if (block.isInitialized() && block.isLoaded()) {
                out.add(block);
            }
        }
        return List.copyOf(out);
    }

    private static boolean isNccMtkAliasPair(MemoryBlock mirror, MemoryBlock main) {
        return mirror != null && main != null && mirror.isInitialized() && main.isInitialized() &&
            mirror.isLoaded() && main.isLoaded() && mirror.getStart().getOffset() == 0 &&
            main.getStart().getOffset() == MTK_RUNTIME_ALIAS && mirror.getSize() == main.getSize();
    }
}
