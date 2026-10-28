package mtk_mddb.ghidra;

import java.io.BufferedWriter;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;
import java.util.function.Consumer;

import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;

/** Implementation behind the stable CompareMtkBuilds Ghidra script wrapper. */
public final class CompareMtkBuildsRunner {
    private CompareMtkBuildsRunner() {}

    public static void run(Program source, Program target, Path sourceEdb, Path targetEdb,
            Path output, boolean withBsim, boolean withVersionTracking, TaskMonitor monitor,
            Consumer<String> log) throws Exception {
        try (MddbDatabase leftMddb = MddbDatabase.open(sourceEdb);
             MddbDatabase rightMddb = MddbDatabase.open(targetEdb)) {
            CrossBuildComparator.Result result = CrossBuildComparator.compare(
                source, target, leftMddb, rightMddb, withBsim, monitor);
            MddbDatabase.SemanticEnumDiff enumDiff = leftMddb.compareSemanticEnums(rightMddb);
            VersionTrackingComparator.Result vtResult = withVersionTracking
                ? VersionTrackingComparator.compare(source, target, monitor) : null;
            String sourceScope = ProgramComparisonScope.description(source);
            String targetScope = ProgramComparisonScope.description(target);
            writeReport(output, leftMddb.compareRaw(rightMddb), enumDiff, result, vtResult,
                sourceScope, targetScope);
            log.accept("MTK_CROSS_BUILD_DIFF=" + output);
            log.accept("SOURCE_SCOPE=" + sourceScope);
            log.accept("TARGET_SCOPE=" + targetScope);
            log.accept("COMMON_MDDB_STRINGS=" + result.commonMddbStrings());
            log.accept("PROGRAM_STRINGS_COMMON=" + result.programStringDiff().commonStrings());
            log.accept("PROGRAM_STRINGS_ONLY_SOURCE=" + result.programStringDiff().onlySource());
            log.accept("PROGRAM_STRINGS_ONLY_TARGET=" + result.programStringDiff().onlyTarget());
            log.accept("PROGRAM_STRING_RUNS=" + result.programStringRuns().size());
            log.accept("SEMANTIC_ENUM_IDENTICAL=" + enumDiff.identicalEnums());
            log.accept("SEMANTIC_ENUM_CHANGED=" + enumDiff.changedEnums());
            log.accept("PAIRED_FUNCTIONS=" + result.pairs().size());
            log.accept("FID_FULL_MATCHED_FUNCTIONS=" + result.fidCoverage().fullHashMatchedFunctions());
            log.accept("FID_SPECIFIC_MATCHED_FUNCTIONS=" + result.fidCoverage().specificHashMatchedFunctions());
            log.accept("UNIQUE_FULL_FID_PAIRS=" + result.exactFidPairs().size());
            log.accept("EXACT_SPECIFIC_FID=" + result.exactSpecificFidPairs());
            log.accept("EXACT_FULL_FID=" + result.exactFullFidPairs());
            if (vtResult != null) {
                log.accept("VT_ACCEPTED_FUNCTION_ASSOCIATIONS=" +
                    vtResult.acceptedFunctionAssociations());
                log.accept("VT_ACCEPTED_DATA_ASSOCIATIONS=" + vtResult.acceptedDataAssociations());
                log.accept("VT_MATCH_ROWS=" + vtResult.matches().size());
                for (VersionTrackingComparator.Stage stage : vtResult.stages()) {
                    log.accept("VT_STAGE=" + stage.correlator() + " matches=" + stage.matches() +
                        " accepted=" + stage.newlyAccepted());
                }
            }
        }
    }

    private static void writeReport(Path output,
            Map<String, MddbDatabase.ColumnFamilyDiff> rawDiff,
            MddbDatabase.SemanticEnumDiff enumDiff,
            CrossBuildComparator.Result result,
            VersionTrackingComparator.Result vtResult, String sourceScope, String targetScope)
            throws Exception {
        Path parent = output.toAbsolutePath().getParent();
        if (parent != null) {
            Files.createDirectories(parent);
        }
        try (BufferedWriter writer = Files.newBufferedWriter(output)) {
            writer.write("summary\tsource_scope\t" + clean(sourceScope) + "\n");
            writer.write("summary\ttarget_scope\t" + clean(targetScope) + "\n");
            writer.write("section\tmetric\tleft\tright\tcommon\tidentical\tchanged\tonly_left\tonly_right\n");
            for (Map.Entry<String, MddbDatabase.ColumnFamilyDiff> entry : rawDiff.entrySet()) {
                MddbDatabase.ColumnFamilyDiff d = entry.getValue();
                writer.write(String.join("\t", "mddb_cf", clean(entry.getKey()),
                    Long.toString(d.leftRecords()), Long.toString(d.rightRecords()),
                    Long.toString(d.commonKeys()), Long.toString(d.identicalValues()),
                    Long.toString(d.changedValues()), Long.toString(d.onlyLeft()),
                    Long.toString(d.onlyRight())));
                writer.write("\n");
            }
            writer.write("summary\tsemantic_enums_left\t" + enumDiff.leftEnums() + "\n");
            writer.write("summary\tsemantic_enums_right\t" + enumDiff.rightEnums() + "\n");
            writer.write("summary\tsemantic_enums_common\t" + enumDiff.commonNames() + "\n");
            writer.write("summary\tsemantic_enums_identical\t" + enumDiff.identicalEnums() + "\n");
            writer.write("summary\tsemantic_enums_changed\t" + enumDiff.changedEnums() + "\n");
            writer.write("summary\tsemantic_enums_only_left\t" + enumDiff.onlyLeft() + "\n");
            writer.write("summary\tsemantic_enums_only_right\t" + enumDiff.onlyRight() + "\n");
            for (MddbDatabase.SemanticEnumChange change : enumDiff.changes()) {
                writer.write("enum_delta\tchanged\t" + clean(change.name()) + "\t" +
                    change.leftSize() + "\t" + change.rightSize() + "\n");
                for (String member : change.removedMembers()) {
                    writer.write("enum_member_delta\tremoved\t" + clean(change.name()) +
                        "\t" + clean(member) + "\n");
                }
                for (String member : change.addedMembers()) {
                    writer.write("enum_member_delta\tadded\t" + clean(change.name()) +
                        "\t" + clean(member) + "\n");
                }
                for (String member : change.renumberedMembers()) {
                    writer.write("enum_member_delta\trenumbered\t" + clean(change.name()) +
                        "\t" + clean(member) + "\n");
                }
            }
            for (String name : enumDiff.onlyLeftNames()) {
                writer.write("enum_delta\tonly_left\t" + clean(name) + "\n");
            }
            for (String name : enumDiff.onlyRightNames()) {
                writer.write("enum_delta\tonly_right\t" + clean(name) + "\n");
            }
            writer.write("summary\tcommon_mddb_strings\t" + result.commonMddbStrings() + "\n");
            CrossBuildComparator.ProgramStringDiff programStrings = result.programStringDiff();
            writer.write("summary\tprogram_strings_source\t" + programStrings.sourceStrings() + "\n");
            writer.write("summary\tprogram_strings_target\t" + programStrings.targetStrings() + "\n");
            writer.write("summary\tprogram_strings_common\t" + programStrings.commonStrings() + "\n");
            writer.write("summary\tprogram_strings_only_source\t" + programStrings.onlySource() + "\n");
            writer.write("summary\tprogram_strings_only_target\t" + programStrings.onlyTarget() + "\n");
            for (String value : programStrings.onlySourceValues()) {
                writer.write("program_string_delta\tonly_source\t" + clean(value) + "\n");
            }
            for (String value : programStrings.onlyTargetValues()) {
                writer.write("program_string_delta\tonly_target\t" + clean(value) + "\n");
            }
            writer.write("summary\tprogram_string_runs\t" + result.programStringRuns().size() + "\n");
            for (mtk_mddb.ghidra.ProgramStringIndex.MatchingRun run : result.programStringRuns()) {
                writer.write(String.join("\t", "program_string_run",
                    run.sourceStart().toString(), run.sourceEnd().toString(),
                    run.targetStart().toString(), run.targetEnd().toString(),
                    Integer.toString(run.strings()), Long.toString(run.addressDelta()),
                    clean(run.firstValue()), clean(run.lastValue())));
                writer.write("\n");
            }
            writer.write("summary\tsource_anchors_in_program\t" + result.sourceAnchorsInProgram() + "\n");
            writer.write("summary\ttarget_anchors_in_program\t" + result.targetAnchorsInProgram() + "\n");
            writer.write("summary\tunique_cross_build_anchors\t" + result.uniqueCrossBuildAnchors() + "\n");
            writer.write("summary\tpaired_functions\t" + result.pairs().size() + "\n");
            CrossBuildComparator.FidCoverage coverage = result.fidCoverage();
            writer.write("summary\tsource_functions\t" + coverage.sourceFunctions() + "\n");
            writer.write("summary\ttarget_functions\t" + coverage.targetFunctions() + "\n");
            writer.write("summary\tsource_fid_hashable\t" + coverage.sourceHashable() + "\n");
            writer.write("summary\ttarget_fid_hashable\t" + coverage.targetHashable() + "\n");
            writer.write("summary\tfull_fid_matched_functions\t" + coverage.fullHashMatchedFunctions() + "\n");
            writer.write("summary\tfull_fid_unique_pairs\t" + coverage.fullHashUniquePairs() + "\n");
            writer.write("summary\tspecific_fid_matched_functions\t" + coverage.specificHashMatchedFunctions() + "\n");
            writer.write("summary\tspecific_fid_unique_pairs\t" + coverage.specificHashUniquePairs() + "\n");
            writer.write("summary\tunique_full_fid_pairs\t" + result.exactFidPairs().size() + "\n");
            writer.write("summary\texact_specific_fid_pairs\t" + result.exactSpecificFidPairs() + "\n");
            writer.write("summary\texact_full_fid_pairs\t" + result.exactFullFidPairs() + "\n");
            writer.write("\nfid_source_address\tfid_target_address\tsource_name\ttarget_name\t" +
                "code_units\tfull_fid\tspecific_fid\tspecific_additional_size\n");
            for (CrossBuildComparator.ExactFidPair pair : result.exactFidPairs()) {
                writer.write(String.join("\t",
                    ProgramComparisonScope.canonicalAddress(
                        pair.source().getProgram(), pair.source().getEntryPoint()).toString(),
                    ProgramComparisonScope.canonicalAddress(
                        pair.target().getProgram(), pair.target().getEntryPoint()).toString(),
                    clean(pair.source().getName()), clean(pair.target().getName()),
                    Short.toString(pair.sourceFid().codeUnitSize()), hex(pair.sourceFid().fullHash()),
                    hex(pair.sourceFid().specificHash()),
                    Byte.toString(pair.sourceFid().specificAdditionalSize())));
                writer.write("\n");
            }

            writer.write("\nsource_address\ttarget_address\tsource_name\ttarget_name\tanchors\tanchor_count\t" +
                "source_fid_specific\ttarget_fid_specific\tsame_specific\t" +
                "source_fid_full\ttarget_fid_full\tsame_full\tbsim_similarity\tbsim_significance\n");
            for (CrossBuildComparator.FunctionPair pair : result.pairs()) {
                String sourceSpecific = pair.sourceFid() == null ? "" : hex(pair.sourceFid().specificHash());
                String targetSpecific = pair.targetFid() == null ? "" : hex(pair.targetFid().specificHash());
                String sourceFull = pair.sourceFid() == null ? "" : hex(pair.sourceFid().fullHash());
                String targetFull = pair.targetFid() == null ? "" : hex(pair.targetFid().fullHash());
                String similarity = pair.bsim() == null ? "" : Double.toString(pair.bsim().similarity());
                String significance = pair.bsim() == null ? "" : Double.toString(pair.bsim().significance());
                writer.write(String.join("\t",
                    ProgramComparisonScope.canonicalAddress(
                        pair.source().getProgram(), pair.source().getEntryPoint()).toString(),
                    ProgramComparisonScope.canonicalAddress(
                        pair.target().getProgram(), pair.target().getEntryPoint()).toString(),
                    clean(pair.source().getName()), clean(pair.target().getName()),
                    clean(String.join(" | ", pair.anchors())), Integer.toString(pair.anchors().size()),
                    sourceSpecific, targetSpecific, Boolean.toString(pair.sameSpecificFid()),
                    sourceFull, targetFull, Boolean.toString(pair.sameFullFid()),
                    similarity, significance));
                writer.write("\n");
            }

            if (vtResult != null) {
                writer.write("summary\tvt_accepted_function_associations\t" +
                    vtResult.acceptedFunctionAssociations() + "\n");
                writer.write("summary\tvt_accepted_data_associations\t" +
                    vtResult.acceptedDataAssociations() + "\n");
                writer.write("summary\tvt_match_rows\t" + vtResult.matches().size() + "\n");
                for (VersionTrackingComparator.Stage stage : vtResult.stages()) {
                    writer.write("vt_stage\t" + clean(stage.correlator()) + "\t" +
                        stage.matches() + "\t" + stage.newlyAccepted() + "\n");
                }
                writer.write("\nvt_correlator\tsource_address\ttarget_address\tsource_name\t" +
                    "target_name\tsimilarity\tconfidence\tstatus\n");
                for (VersionTrackingComparator.Match match : vtResult.matches()) {
                    writer.write(String.join("\t", clean(match.correlator()),
                        match.source().toString(), match.target().toString(),
                        clean(match.sourceName()), clean(match.targetName()),
                        Double.toString(match.similarity()), Double.toString(match.confidence()),
                        match.status()));
                    writer.write("\n");
                }
            }
        }
    }

    private static String hex(long value) {
        return Long.toUnsignedString(value, 16);
    }

    private static String clean(String value) {
        return value == null ? "" : value.replace("\t", " ").replace("\n", " ").replace("\r", " ");
    }
}
