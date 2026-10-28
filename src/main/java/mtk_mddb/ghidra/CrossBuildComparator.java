package mtk_mddb.ghidra;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import generic.lsh.vector.LSHVector;
import generic.lsh.vector.LSHVectorFactory;
import generic.lsh.vector.VectorCompare;
import ghidra.app.decompiler.DecompileException;
import ghidra.feature.fid.hash.FidHashQuad;
import ghidra.feature.fid.service.FidService;
import ghidra.features.bsim.query.FunctionDatabase;
import ghidra.features.bsim.query.GenSignatures;
import ghidra.features.bsim.query.LSHException;
import ghidra.features.bsim.query.client.Configuration;
import ghidra.features.bsim.query.description.FunctionDescription;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Cross-build function comparison anchored by vocabulary shared between two MediaTek MDDBs.
 *
 * <p>The MDDB strings provide cheap semantic anchors that survive relinking. Functions are paired
 * only when one shared string resolves to exactly one referencing function in each program. FID
 * hashes then identify relocation-insensitive exact matches. Optional BSim is run only over the
 * already-paired functions, avoiding an O(N^2) all-functions comparison.</p>
 */
public final class CrossBuildComparator {
    private static final String BSIM_TEMPLATE = "medium_nosize";
    private static final int MIN_ANCHOR_LENGTH = 4;
    private static final int MAX_ANCHOR_LENGTH = 256;

    public record FidSignature(short codeUnitSize, long fullHash, long specificHash,
            byte specificAdditionalSize) {}

    public record BsimScore(double similarity, double significance) {}

    public record FidCoverage(int sourceFunctions, int targetFunctions, int sourceHashable,
            int targetHashable, int fullHashMatchedFunctions, int fullHashUniquePairs,
            int specificHashMatchedFunctions, int specificHashUniquePairs) {}

    public record ExactFidPair(Function source, Function target, FidSignature sourceFid,
            FidSignature targetFid) {}

    public record ProgramStringDiff(int sourceStrings, int targetStrings, int commonStrings,
            int onlySource, int onlyTarget, List<String> onlySourceValues,
            List<String> onlyTargetValues) {}

    private record FullFidKey(short codeUnitSize, long fullHash) {}

    private record SpecificFidKey(short codeUnitSize, long specificHash, byte additionalSize) {}

    public record FunctionPair(Function source, Function target, List<String> anchors,
            FidSignature sourceFid, FidSignature targetFid, BsimScore bsim) {
        public boolean sameFullFid() {
            return sourceFid != null && targetFid != null &&
                sourceFid.codeUnitSize() == targetFid.codeUnitSize() &&
                sourceFid.fullHash() == targetFid.fullHash();
        }

        public boolean sameSpecificFid() {
            return sourceFid != null && targetFid != null &&
                sourceFid.codeUnitSize() == targetFid.codeUnitSize() &&
                sourceFid.specificHash() == targetFid.specificHash() &&
                sourceFid.specificAdditionalSize() == targetFid.specificAdditionalSize();
        }
    }

    public record Result(int commonMddbStrings, ProgramStringDiff programStringDiff,
            List<ProgramStringIndex.MatchingRun> programStringRuns, int sourceAnchorsInProgram,
            int targetAnchorsInProgram, int uniqueCrossBuildAnchors, FidCoverage fidCoverage,
            List<ExactFidPair> exactFidPairs, List<FunctionPair> pairs) {
        public long exactSpecificFidPairs() {
            return pairs.stream().filter(FunctionPair::sameSpecificFid).count();
        }

        public long exactFullFidPairs() {
            return pairs.stream().filter(FunctionPair::sameFullFid).count();
        }
    }

    private record AddressPair(Address source, Address target) {}

    private CrossBuildComparator() {}

    public static Result compare(Program source, Program target, MddbDatabase sourceMddb,
            MddbDatabase targetMddb, boolean withBsim, TaskMonitor monitor)
            throws Exception {
        Set<String> sourceStrings = sourceMddb.stringPoolStrings(MIN_ANCHOR_LENGTH,
            MAX_ANCHOR_LENGTH);
        Set<String> commonStrings = new HashSet<>(sourceStrings);
        commonStrings.retainAll(targetMddb.stringPoolStrings(MIN_ANCHOR_LENGTH,
            MAX_ANCHOR_LENGTH));

        List<ProgramStringIndex.RawString> sourceRawStrings = ProgramStringIndex.asciiStrings(
            source, MIN_ANCHOR_LENGTH, MAX_ANCHOR_LENGTH, monitor);
        List<ProgramStringIndex.RawString> targetRawStrings = ProgramStringIndex.asciiStrings(
            target, MIN_ANCHOR_LENGTH, MAX_ANCHOR_LENGTH, monitor);
        ProgramStringDiff programStringDiff = programStringDiff(sourceRawStrings, targetRawStrings);
        List<ProgramStringIndex.MatchingRun> programStringRuns = ProgramStringIndex.matchingRuns(
            sourceRawStrings, targetRawStrings, 8);

        Map<String, Set<Function>> sourceIndex = indexProgramStrings(
            source, sourceRawStrings, commonStrings, monitor);
        Map<String, Set<Function>> targetIndex = indexProgramStrings(
            target, targetRawStrings, commonStrings, monitor);

        LinkedHashMap<AddressPair, LinkedHashSet<String>> anchorsByPair = new LinkedHashMap<>();
        int uniqueAnchors = 0;
        for (String anchor : commonStrings) {
            monitor.checkCancelled();
            Set<Function> left = sourceIndex.get(anchor);
            Set<Function> right = targetIndex.get(anchor);
            if (left == null || right == null || left.size() != 1 || right.size() != 1) {
                continue;
            }
            Function leftFunction = left.iterator().next();
            Function rightFunction = right.iterator().next();
            AddressPair key = new AddressPair(leftFunction.getEntryPoint(), rightFunction.getEntryPoint());
            anchorsByPair.computeIfAbsent(key, ignored -> new LinkedHashSet<>()).add(anchor);
            uniqueAnchors++;
        }

        Map<Address, ghidra.program.model.listing.Function> sourceFunctions = functionsByEntry(source,
            anchorsByPair.keySet().stream().map(AddressPair::source).toList());
        Map<Address, ghidra.program.model.listing.Function> targetFunctions = functionsByEntry(target,
            anchorsByPair.keySet().stream().map(AddressPair::target).toList());

        FidService fidService = new FidService();
        List<ghidra.program.model.listing.Function> allSourceFunctions = nonThunkFunctions(source);
        List<ghidra.program.model.listing.Function> allTargetFunctions = nonThunkFunctions(target);
        Map<Address, FidSignature> sourceFids = hashFunctions(fidService, allSourceFunctions, monitor);
        Map<Address, FidSignature> targetFids = hashFunctions(fidService, allTargetFunctions, monitor);
        FidCoverage fidCoverage = fidCoverage(allSourceFunctions.size(), allTargetFunctions.size(),
            sourceFids, targetFids);
        List<ExactFidPair> exactFidPairs = uniqueFullFidPairs(source, target, sourceFids, targetFids);

        Map<Address, LSHVector> sourceVectors = Map.of();
        Map<Address, LSHVector> targetVectors = Map.of();
        LSHVectorFactory vectorFactory = null;
        if (withBsim && !anchorsByPair.isEmpty()) {
            vectorFactory = createVectorFactory();
            sourceVectors = bsimVectors(source, sourceFunctions.values(), vectorFactory, monitor);
            targetVectors = bsimVectors(target, targetFunctions.values(), vectorFactory, monitor);
        }

        List<FunctionPair> pairs = new ArrayList<>(anchorsByPair.size());
        for (Map.Entry<AddressPair, LinkedHashSet<String>> entry : anchorsByPair.entrySet()) {
            monitor.checkCancelled();
            AddressPair key = entry.getKey();
            Function left = sourceFunctions.get(key.source());
            Function right = targetFunctions.get(key.target());
            if (left == null || right == null) {
                continue;
            }
            BsimScore bsim = null;
            if (vectorFactory != null) {
                LSHVector leftVector = sourceVectors.get(key.source());
                LSHVector rightVector = targetVectors.get(key.target());
                if (leftVector != null && rightVector != null) {
                    VectorCompare comparison = new VectorCompare();
                    double similarity = leftVector.compare(rightVector, comparison);
                    double significance = vectorFactory.calculateSignificance(comparison);
                    bsim = new BsimScore(similarity, significance);
                }
            }
            List<String> anchors = new ArrayList<>(entry.getValue());
            Collections.sort(anchors);
            pairs.add(new FunctionPair(left, right, List.copyOf(anchors),
                sourceFids.get(key.source()), targetFids.get(key.target()), bsim));
        }
        pairs.sort((a, b) -> {
            int byAnchors = Integer.compare(b.anchors().size(), a.anchors().size());
            if (byAnchors != 0) {
                return byAnchors;
            }
            return a.source().getEntryPoint().compareTo(b.source().getEntryPoint());
        });

        return new Result(commonStrings.size(), programStringDiff, programStringRuns,
            sourceIndex.size(), targetIndex.size(), uniqueAnchors, fidCoverage, exactFidPairs,
            List.copyOf(pairs));
    }


    private static ProgramStringDiff programStringDiff(
            List<ProgramStringIndex.RawString> sourceStrings,
            List<ProgramStringIndex.RawString> targetStrings) {
        Set<String> source = new HashSet<>();
        Set<String> target = new HashSet<>();
        for (ProgramStringIndex.RawString string : sourceStrings) {
            source.add(string.value());
        }
        for (ProgramStringIndex.RawString string : targetStrings) {
            target.add(string.value());
        }
        Set<String> common = new HashSet<>(source);
        common.retainAll(target);
        List<String> onlySource = new ArrayList<>(source);
        onlySource.removeAll(target);
        Collections.sort(onlySource);
        List<String> onlyTarget = new ArrayList<>(target);
        onlyTarget.removeAll(source);
        Collections.sort(onlyTarget);
        return new ProgramStringDiff(source.size(), target.size(), common.size(),
            onlySource.size(), onlyTarget.size(), List.copyOf(onlySource), List.copyOf(onlyTarget));
    }

    private static Map<String, Set<Function>> indexProgramStrings(Program program,
            List<ProgramStringIndex.RawString> rawStrings, Set<String> anchors, TaskMonitor monitor)
            throws CancelledException {
        LinkedHashMap<String, Set<Function>> out = new LinkedHashMap<>();
        for (ProgramStringIndex.RawString string : rawStrings) {
            monitor.checkCancelled();
            String value = string.value();
            if (!anchors.contains(value)) {
                continue;
            }
            LinkedHashSet<Function> functions = new LinkedHashSet<>();
            for (Address targetAddress :
                    ProgramComparisonScope.equivalentAddresses(program, string.address())) {
                ReferenceIterator references =
                    program.getReferenceManager().getReferencesTo(targetAddress);
                while (references.hasNext()) {
                    Reference reference = references.next();
                    Function function = ProgramComparisonScope.canonicalFunctionContaining(
                        program, reference.getFromAddress());
                    if (function != null && !function.isThunk()) {
                        functions.add(function);
                    }
                }
            }
            if (!functions.isEmpty()) {
                out.computeIfAbsent(value, ignored -> new LinkedHashSet<>()).addAll(functions);
            }
        }
        return out;
    }

    private static List<ghidra.program.model.listing.Function> nonThunkFunctions(Program program) {
        return ProgramComparisonScope.functions(program).stream()
            .filter(function -> !function.isThunk())
            .toList();
    }

    private static FidCoverage fidCoverage(int sourceFunctions, int targetFunctions,
            Map<Address, FidSignature> source, Map<Address, FidSignature> target) {
        MatchCounts full = matchCounts(source.values(), target.values(),
            signature -> new FullFidKey(signature.codeUnitSize(), signature.fullHash()));
        MatchCounts specific = matchCounts(source.values(), target.values(),
            signature -> new SpecificFidKey(signature.codeUnitSize(), signature.specificHash(),
                signature.specificAdditionalSize()));
        return new FidCoverage(sourceFunctions, targetFunctions, source.size(), target.size(),
            full.matchedFunctions(), full.uniquePairs(), specific.matchedFunctions(),
            specific.uniquePairs());
    }

    private record MatchCounts(int matchedFunctions, int uniquePairs) {}

    private static List<ExactFidPair> uniqueFullFidPairs(Program sourceProgram,
            Program targetProgram, Map<Address, FidSignature> source,
            Map<Address, FidSignature> target) {
        Map<FullFidKey, List<Address>> sourceByKey = new HashMap<>();
        Map<FullFidKey, List<Address>> targetByKey = new HashMap<>();
        for (Map.Entry<Address, FidSignature> entry : source.entrySet()) {
            FidSignature signature = entry.getValue();
            FullFidKey key = new FullFidKey(signature.codeUnitSize(), signature.fullHash());
            sourceByKey.computeIfAbsent(key, ignored -> new ArrayList<>()).add(entry.getKey());
        }
        for (Map.Entry<Address, FidSignature> entry : target.entrySet()) {
            FidSignature signature = entry.getValue();
            FullFidKey key = new FullFidKey(signature.codeUnitSize(), signature.fullHash());
            targetByKey.computeIfAbsent(key, ignored -> new ArrayList<>()).add(entry.getKey());
        }

        List<ExactFidPair> pairs = new ArrayList<>();
        for (Map.Entry<FullFidKey, List<Address>> entry : sourceByKey.entrySet()) {
            List<Address> sourceAddresses = entry.getValue();
            List<Address> targetAddresses = targetByKey.get(entry.getKey());
            if (sourceAddresses.size() != 1 || targetAddresses == null || targetAddresses.size() != 1) {
                continue;
            }
            Address sourceAddress = sourceAddresses.get(0);
            Address targetAddress = targetAddresses.get(0);
            Function sourceFunction = sourceProgram.getFunctionManager().getFunctionAt(sourceAddress);
            Function targetFunction = targetProgram.getFunctionManager().getFunctionAt(targetAddress);
            if (sourceFunction == null || targetFunction == null) {
                continue;
            }
            pairs.add(new ExactFidPair(sourceFunction, targetFunction,
                source.get(sourceAddress), target.get(targetAddress)));
        }
        pairs.sort((left, right) ->
            left.source().getEntryPoint().compareTo(right.source().getEntryPoint()));
        return List.copyOf(pairs);
    }

    private static <K> MatchCounts matchCounts(Collection<FidSignature> left,
            Collection<FidSignature> right, java.util.function.Function<FidSignature, K> keyFunction) {
        Map<K, Integer> leftCounts = new HashMap<>();
        Map<K, Integer> rightCounts = new HashMap<>();
        for (FidSignature signature : left) {
            leftCounts.merge(keyFunction.apply(signature), 1, Integer::sum);
        }
        for (FidSignature signature : right) {
            rightCounts.merge(keyFunction.apply(signature), 1, Integer::sum);
        }
        int matched = 0;
        int unique = 0;
        for (Map.Entry<K, Integer> entry : leftCounts.entrySet()) {
            Integer rightCount = rightCounts.get(entry.getKey());
            if (rightCount == null) {
                continue;
            }
            matched += Math.min(entry.getValue(), rightCount);
            if (entry.getValue() == 1 && rightCount == 1) {
                unique++;
            }
        }
        return new MatchCounts(matched, unique);
    }

    private static Map<Address, Function> functionsByEntry(Program program,
            Collection<Address> addresses) {
        LinkedHashMap<Address, Function> out = new LinkedHashMap<>();
        for (Address address : new LinkedHashSet<>(addresses)) {
            Function function = program.getFunctionManager().getFunctionAt(address);
            if (function != null) {
                out.put(address, function);
            }
        }
        return out;
    }

    private static Map<Address, FidSignature> hashFunctions(FidService service,
            Collection<Function> functions, TaskMonitor monitor) throws CancelledException {
        LinkedHashMap<Address, FidSignature> out = new LinkedHashMap<>();
        for (Function function : functions) {
            monitor.checkCancelled();
            try {
                FidHashQuad hash = service.hashFunction(function);
                if (hash != null) {
                    out.put(function.getEntryPoint(), new FidSignature(hash.getCodeUnitSize(),
                        hash.getFullHash(), hash.getSpecificHash(),
                        hash.getSpecificHashAdditionalSize()));
                }
            } catch (MemoryAccessException ignored) {
                // Partially recovered modem programs can contain functions crossing unmapped regions.
                // Treat those as unhashable rather than failing the entire cross-build comparison.
            }
        }
        return out;
    }

    private static LSHVectorFactory createVectorFactory() throws LSHException {
        LSHVectorFactory factory = FunctionDatabase.generateLSHVectorFactory();
        Configuration config = FunctionDatabase.loadConfigurationTemplate(BSIM_TEMPLATE);
        factory.set(config.weightfactory, config.idflookup, config.info.settings);
        return factory;
    }

    private static Map<Address, LSHVector> bsimVectors(Program program,
            Collection<Function> functions, LSHVectorFactory vectorFactory, TaskMonitor monitor)
            throws LSHException, DecompileException {
        if (functions.isEmpty()) {
            return Map.of();
        }
        GenSignatures signatures = new GenSignatures(false);
        try {
            signatures.setVectorFactory(vectorFactory);
            signatures.openProgram(program, null, null, null, null, null);
            signatures.scanFunctions(functions.iterator(), functions.size(), monitor);
            LinkedHashMap<Address, LSHVector> out = new LinkedHashMap<>();
            Iterator<FunctionDescription> descriptions =
                signatures.getDescriptionManager().listAllFunctions();
            while (descriptions.hasNext()) {
                FunctionDescription description = descriptions.next();
                if (description.getSignatureRecord() == null) {
                    continue;
                }
                Address address = program.getAddressFactory().getDefaultAddressSpace().getAddress(
                    description.getAddress());
                out.put(address, description.getSignatureRecord().getLSHVector());
            }
            return out;
        } finally {
            signatures.dispose();
        }
    }
}
