package mtk_mddb.ghidra;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import ghidra.feature.vt.api.correlator.program.CombinedFunctionAndDataReferenceProgramCorrelatorFactory;
import ghidra.feature.vt.api.correlator.program.DuplicateFunctionMatchProgramCorrelatorFactory;
import ghidra.feature.vt.api.correlator.program.ExactDataMatchProgramCorrelatorFactory;
import ghidra.feature.vt.api.correlator.program.ExactMatchBytesProgramCorrelatorFactory;
import ghidra.feature.vt.api.correlator.program.ExactMatchInstructionsProgramCorrelatorFactory;
import ghidra.feature.vt.api.correlator.program.ExactMatchMnemonicsProgramCorrelatorFactory;
import ghidra.feature.vt.api.correlator.program.FunctionReferenceProgramCorrelatorFactory;
import ghidra.feature.vt.api.correlator.program.VTAbstractReferenceProgramCorrelatorFactory;
import ghidra.feature.vt.api.db.VTSessionDB;
import ghidra.feature.vt.api.main.VTAssociation;
import ghidra.feature.vt.api.main.VTAssociationManager;
import ghidra.feature.vt.api.main.VTAssociationStatus;
import ghidra.feature.vt.api.main.VTAssociationType;
import ghidra.feature.vt.api.main.VTMatch;
import ghidra.feature.vt.api.main.VTMatchSet;
import ghidra.feature.vt.api.main.VTProgramCorrelator;
import ghidra.feature.vt.api.main.VTProgramCorrelatorFactory;
import ghidra.feature.vt.api.util.VTOptions;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.lang.OperandType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Program;
import ghidra.program.model.scalar.Scalar;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Read-only cross-build matching using Ghidra's Version Tracking correlators.
 *
 * <p>The transient VT session is allowed to accept associations because later correlators use
 * accepted matches as seeds, but no markup task is ever run, so neither input Program is modified.
 * Duplicate exact-instruction candidates are conservatively disambiguated using the same scalar /
 * address-operand idea as Ghidra Auto Version Tracking: a pair is accepted only when the operand
 * map is unique in both directions.</p>
 */
public final class VersionTrackingComparator {
    private static final double REFERENCE_SIMILARITY_THRESHOLD = 0.95;
    private static final double REFERENCE_CONFIDENCE_THRESHOLD = 10.0;

    public record Match(String correlator, Address source, Address target, String sourceName,
            String targetName, double similarity, double confidence, String status) {}

    public record Stage(String correlator, int matches, int newlyAccepted) {}

    public record Result(List<Stage> stages, List<Match> matches,
            int acceptedFunctionAssociations, int acceptedDataAssociations) {}

    private VersionTrackingComparator() {}

    public static Result compare(Program source, Program target, TaskMonitor monitor)
            throws Exception {
        long sourceModification = source.getModificationNumber();
        long targetModification = target.getModificationNumber();
        Object owner = new Object();
        VTSessionDB session = new VTSessionDB("MediaTek cross-build comparison",
            source, target, owner);
        int transaction = session.startTransaction("Run MediaTek cross-build correlators");
        boolean commit = false;
        try {
            AddressSetView sourceSet = ProgramComparisonScope.addressSet(source);
            AddressSetView targetSet = ProgramComparisonScope.addressSet(target);
            List<Stage> stages = new ArrayList<>();

            // Follow Ghidra Auto Version Tracking's escalation, but never run markup application.
            runStage(new ExactDataMatchProgramCorrelatorFactory(), source, sourceSet, target,
                targetSet, session, VTAssociationType.DATA, stages, monitor);
            for (VTProgramCorrelatorFactory factory : List.of(
                    new ExactMatchBytesProgramCorrelatorFactory(),
                    new ExactMatchInstructionsProgramCorrelatorFactory(),
                    new ExactMatchMnemonicsProgramCorrelatorFactory(),
                    new DuplicateFunctionMatchProgramCorrelatorFactory(),
                    new FunctionReferenceProgramCorrelatorFactory(),
                    new CombinedFunctionAndDataReferenceProgramCorrelatorFactory())) {
                runStage(factory, source, sourceSet, target, targetSet, session,
                    VTAssociationType.FUNCTION, stages, monitor);
            }

            List<Match> matches = collectMatches(session, source, target, monitor);
            int acceptedFunctionAssociations = (int) session.getAssociationManager().getAssociations().stream()
                .filter(association -> association.getStatus() == VTAssociationStatus.ACCEPTED &&
                    association.getType() == VTAssociationType.FUNCTION)
                .count();
            int acceptedDataAssociations = (int) session.getAssociationManager().getAssociations().stream()
                .filter(association -> association.getStatus() == VTAssociationStatus.ACCEPTED &&
                    association.getType() == VTAssociationType.DATA)
                .count();
            if (source.getModificationNumber() != sourceModification ||
                    target.getModificationNumber() != targetModification) {
                throw new IllegalStateException(
                    "Version Tracking comparison unexpectedly modified an input program");
            }
            commit = true;
            return new Result(List.copyOf(stages), List.copyOf(matches),
                acceptedFunctionAssociations, acceptedDataAssociations);
        } finally {
            session.endTransaction(transaction, commit);
            session.release(owner);
        }
    }

    private static void runStage(VTProgramCorrelatorFactory factory, Program source,
            AddressSetView sourceSet, Program target, AddressSetView targetSet, VTSessionDB session,
            VTAssociationType acceptedType, List<Stage> stages, TaskMonitor monitor) throws Exception {
        monitor.checkCancelled();
        VTOptions options = factory.createDefaultOptions();
        if (factory instanceof VTAbstractReferenceProgramCorrelatorFactory) {
            options.setDouble(VTAbstractReferenceProgramCorrelatorFactory.SIMILARITY_THRESHOLD,
                REFERENCE_SIMILARITY_THRESHOLD);
            options.setDouble(VTAbstractReferenceProgramCorrelatorFactory.CONFIDENCE_THRESHOLD,
                REFERENCE_CONFIDENCE_THRESHOLD);
        }
        VTProgramCorrelator correlator = factory.createCorrelator(
            source, sourceSet, target, targetSet, options);
        VTMatchSet matchSet = correlator.correlate(session, monitor);
        int accepted;
        if (factory instanceof DuplicateFunctionMatchProgramCorrelatorFactory) {
            accepted = acceptDuplicateFunctionMatches(matchSet, source, target, session, monitor);
        } else {
            accepted = acceptUniqueMatches(matchSet, acceptedType, monitor);
        }
        stages.add(new Stage(correlator.getName(), matchSet.getMatchCount(), accepted));
    }

    private static int acceptUniqueMatches(VTMatchSet matchSet, VTAssociationType acceptedType,
            TaskMonitor monitor) throws Exception {
        Map<Address, Integer> sourceCounts = new HashMap<>();
        Map<Address, Integer> targetCounts = new HashMap<>();
        for (VTMatch match : matchSet.getMatches()) {
            monitor.checkCancelled();
            VTAssociation association = match.getAssociation();
            if (association.getType() != acceptedType) {
                continue;
            }
            sourceCounts.merge(match.getSourceAddress(), 1, Integer::sum);
            targetCounts.merge(match.getDestinationAddress(), 1, Integer::sum);
        }

        int accepted = 0;
        for (VTMatch match : matchSet.getMatches()) {
            monitor.checkCancelled();
            VTAssociation association = match.getAssociation();
            if (association.getType() != acceptedType ||
                    association.getStatus() != VTAssociationStatus.AVAILABLE ||
                    sourceCounts.getOrDefault(match.getSourceAddress(), 0) != 1 ||
                    targetCounts.getOrDefault(match.getDestinationAddress(), 0) != 1) {
                continue;
            }
            association.setAccepted();
            accepted++;
        }
        return accepted;
    }

    private static int acceptDuplicateFunctionMatches(VTMatchSet matchSet, Program source,
            Program target, VTSessionDB session, TaskMonitor monitor) throws Exception {
        Set<VTAssociation> processed = new HashSet<>();
        Set<VTAssociation> duplicateAssociations = new HashSet<>();
        for (VTMatch match : matchSet.getMatches()) {
            duplicateAssociations.add(match.getAssociation());
        }
        int accepted = 0;
        for (VTMatch match : matchSet.getMatches()) {
            monitor.checkCancelled();
            VTAssociation association = match.getAssociation();
            if (processed.contains(association)) {
                continue;
            }
            if (association.getStatus() != VTAssociationStatus.AVAILABLE) {
                processed.add(association);
                continue;
            }

            Set<VTAssociation> related = getAllRelatedAssociations(session,
                match.getSourceAddress(), match.getDestinationAddress(), monitor);
            List<VTAssociation> unique = findUniqueOperandAssociations(
                related, source, target, session, monitor);
            processed.addAll(related);
            for (VTAssociation candidate : unique) {
                monitor.checkCancelled();
                if (!duplicateAssociations.contains(candidate) ||
                        candidate.getStatus() != VTAssociationStatus.AVAILABLE) {
                    continue;
                }
                candidate.setAccepted();
                accepted++;
            }
        }
        return accepted;
    }

    private static Set<VTAssociation> getAllRelatedAssociations(VTSessionDB session,
            Address source, Address target, TaskMonitor monitor) throws CancelledException {
        VTAssociationManager manager = session.getAssociationManager();
        Collection<VTAssociation> initial =
            manager.getRelatedAssociationsBySourceAndDestinationAddress(source, target);
        Set<VTAssociation> all = new LinkedHashSet<>(initial);
        for (VTAssociation association : initial) {
            monitor.checkCancelled();
            all.addAll(manager.getRelatedAssociationsBySourceAndDestinationAddress(
                association.getSourceAddress(), association.getDestinationAddress()));
        }
        return all;
    }

    private static List<VTAssociation> findUniqueOperandAssociations(
            Collection<VTAssociation> associations, Program source, Program target,
            VTSessionDB session, TaskMonitor monitor) throws CancelledException {
        Map<Function, Map<Long, Map<Integer, Object>>> sourceMaps =
            createFunctionsMap(associations, source, true, monitor);
        Map<Function, Map<Long, Map<Integer, Object>>> targetMaps =
            createFunctionsMap(associations, target, false, monitor);
        if (sourceMaps.isEmpty() || targetMaps.isEmpty()) {
            return List.of();
        }

        List<Function> sources = new ArrayList<>(sourceMaps.keySet());
        List<Function> targets = new ArrayList<>(targetMaps.keySet());
        sources.sort((a, b) -> a.getEntryPoint().compareTo(b.getEntryPoint()));
        targets.sort((a, b) -> a.getEntryPoint().compareTo(b.getEntryPoint()));

        Map<Function, List<Function>> matchesBySource = new LinkedHashMap<>();
        Map<Function, Integer> sourceMatchesByTarget = new HashMap<>();
        for (Function sourceFunction : sources) {
            monitor.checkCancelled();
            List<Function> matches = new ArrayList<>();
            for (Function targetFunction : targets) {
                monitor.checkCancelled();
                if (equivalentFunctionMap(sourceMaps.get(sourceFunction),
                        targetMaps.get(targetFunction), source, target, session, monitor)) {
                    matches.add(targetFunction);
                    sourceMatchesByTarget.merge(targetFunction, 1, Integer::sum);
                }
            }
            matchesBySource.put(sourceFunction, List.copyOf(matches));
        }

        List<VTAssociation> out = new ArrayList<>();
        VTAssociationManager manager = session.getAssociationManager();
        for (Function sourceFunction : sources) {
            List<Function> matches = matchesBySource.get(sourceFunction);
            if (matches == null || matches.size() != 1) {
                continue;
            }
            Function targetFunction = matches.get(0);
            if (sourceMatchesByTarget.getOrDefault(targetFunction, 0) != 1) {
                continue;
            }
            VTAssociation association = manager.getAssociation(
                sourceFunction.getEntryPoint(), targetFunction.getEntryPoint());
            if (association != null) {
                out.add(association);
            }
        }
        return out;
    }

    private static Map<Function, Map<Long, Map<Integer, Object>>> createFunctionsMap(
            Collection<VTAssociation> associations, Program program, boolean source,
            TaskMonitor monitor) throws CancelledException {
        Map<Function, Map<Long, Map<Integer, Object>>> out = new LinkedHashMap<>();
        Set<Function> attempted = new HashSet<>();
        for (VTAssociation association : associations) {
            monitor.checkCancelled();
            Address address = source ? association.getSourceAddress() : association.getDestinationAddress();
            Function function = program.getFunctionManager().getFunctionAt(address);
            if (function == null || !attempted.add(function)) {
                continue;
            }
            Map<Long, Map<Integer, Object>> operands =
                mapFunctionScalarAndAddressOperands(function, monitor);
            if (operands != null) {
                out.put(function, operands);
            }
        }
        return out;
    }

    private static Map<Long, Map<Integer, Object>> mapFunctionScalarAndAddressOperands(
            Function function, TaskMonitor monitor) throws CancelledException {
        Map<Long, Map<Integer, Object>> out = new LinkedHashMap<>();
        InstructionIterator instructions =
            function.getProgram().getListing().getInstructions(function.getBody(), true);
        while (instructions.hasNext()) {
            monitor.checkCancelled();
            Instruction instruction = instructions.next();
            Map<Integer, Object> operands = createOperandsMap(instruction);
            if (!operands.isEmpty()) {
                out.put(offsetInFunction(function, instruction.getAddress()), operands);
            }
        }
        return out.isEmpty() ? null : out;
    }

    private static Map<Integer, Object> createOperandsMap(Instruction instruction) {
        Map<Integer, Object> out = new LinkedHashMap<>();
        for (int index = 0; index < instruction.getNumOperands(); index++) {
            int operandType = instruction.getOperandType(index);
            if (OperandType.isScalar(operandType)) {
                Scalar scalar = instruction.getScalar(index);
                if (scalar != null) {
                    out.put(index, scalar);
                }
            } else if (OperandType.isAddress(operandType) &&
                    (OperandType.isDataReference(operandType) || OperandType.isCodeReference(operandType))) {
                Address address = instruction.getAddress(index);
                if (address != null) {
                    out.put(index, address);
                }
            }
        }
        return out;
    }

    private static boolean equivalentFunctionMap(Map<Long, Map<Integer, Object>> left,
            Map<Long, Map<Integer, Object>> right, Program source, Program target,
            VTSessionDB session, TaskMonitor monitor) throws CancelledException {
        if (!left.keySet().equals(right.keySet())) {
            return false;
        }
        for (Long offset : left.keySet()) {
            monitor.checkCancelled();
            if (!equivalentOperandMap(left.get(offset), right.get(offset),
                    source, target, session, monitor)) {
                return false;
            }
        }
        return true;
    }

    private static boolean equivalentOperandMap(Map<Integer, Object> left,
            Map<Integer, Object> right, Program source, Program target, VTSessionDB session,
            TaskMonitor monitor) throws CancelledException {
        if (!left.keySet().equals(right.keySet())) {
            return false;
        }
        for (Integer index : left.keySet()) {
            monitor.checkCancelled();
            Object leftOperand = left.get(index);
            Object rightOperand = right.get(index);
            if (leftOperand instanceof Scalar) {
                if (!leftOperand.equals(rightOperand)) {
                    return false;
                }
            } else if (!equivalentAddressOperand(leftOperand, rightOperand,
                    source, target, session)) {
                return false;
            }
        }
        return true;
    }

    private static boolean equivalentAddressOperand(Object leftOperand, Object rightOperand,
            Program source, Program target, VTSessionDB session) {
        if (!(leftOperand instanceof Address left) || !(rightOperand instanceof Address right)) {
            return false;
        }

        VTAssociationManager manager = session.getAssociationManager();
        VTAssociation direct = manager.getAssociation(left, right);
        if (direct != null && direct.getStatus() == VTAssociationStatus.ACCEPTED) {
            return true;
        }
        if (!manager.getRelatedAssociationsBySourceAddress(left).isEmpty() ||
                !manager.getRelatedAssociationsByDestinationAddress(right).isEmpty()) {
            return false;
        }
        return sameOperandType(left, right, source, target);
    }

    private static boolean sameOperandType(Address left, Address right,
            Program source, Program target) {
        Function sourceFunction = source.getFunctionManager().getFunctionAt(left);
        if (sourceFunction != null) {
            return target.getFunctionManager().getFunctionAt(right) != null;
        }

        sourceFunction = source.getFunctionManager().getFunctionContaining(left);
        if (sourceFunction != null) {
            Function targetFunction = target.getFunctionManager().getFunctionContaining(right);
            return targetFunction != null &&
                offsetInFunction(sourceFunction, left) == offsetInFunction(targetFunction, right);
        }

        Data sourceData = source.getListing().getDataAt(left);
        Data targetData = target.getListing().getDataAt(right);
        return sourceData != null && targetData != null && sourceData.isDefined() &&
            targetData.isDefined() &&
            sourceData.getDataType().getName().equals(targetData.getDataType().getName());
    }

    private static long offsetInFunction(Function function, Address address) {
        return address.getOffset() - function.getEntryPoint().getOffset();
    }

    private static List<Match> collectMatches(VTSessionDB session, Program source, Program target,
            TaskMonitor monitor) throws CancelledException {
        LinkedHashMap<String, Match> out = new LinkedHashMap<>();
        for (VTMatchSet matchSet : session.getMatchSets()) {
            String correlator = matchSet.getProgramCorrelatorInfo().getName();
            for (VTMatch match : matchSet.getMatches()) {
                monitor.checkCancelled();
                VTAssociation association = match.getAssociation();
                if (association.getType() != VTAssociationType.FUNCTION) {
                    continue;
                }
                Address sourceAddress = match.getSourceAddress();
                Address targetAddress = match.getDestinationAddress();
                Function sourceFunction = source.getFunctionManager().getFunctionAt(sourceAddress);
                Function targetFunction = target.getFunctionManager().getFunctionAt(targetAddress);
                String key = correlator + "\u0000" + sourceAddress + "\u0000" + targetAddress;
                out.putIfAbsent(key, new Match(correlator, sourceAddress, targetAddress,
                    sourceFunction == null ? "" : sourceFunction.getName(),
                    targetFunction == null ? "" : targetFunction.getName(),
                    match.getSimilarityScore().getScore(), match.getConfidenceScore().getScore(),
                    association.getStatus().name()));
            }
        }
        return new ArrayList<>(out.values());
    }
}
