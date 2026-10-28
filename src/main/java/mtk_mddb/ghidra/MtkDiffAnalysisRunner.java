package mtk_mddb.ghidra;

import java.util.function.Consumer;

import ghidra.framework.options.Options;
import ghidra.program.model.listing.Program;

/** Implementation behind the stable MtkDiffAnalysis Ghidra script wrapper. */
public final class MtkDiffAnalysisRunner {
    private MtkDiffAnalysisRunner() {}

    public static void configure(Program program, Consumer<String> log) {
        Options options = program.getOptions(Program.ANALYSIS_PROPERTIES);

        setIfPresent(options, "Decompiler Parameter ID", false, log);
        setIfPresent(options, "Call Convention ID", false, log);
        setIfPresent(options, "Decompiler Switch Analysis", false, log);
        setIfPresent(options, "Stack", false, log);
        setIfPresent(options, "Variadic Function Signature Override", false, log);
        setIfPresent(options, "Apply Data Archives", false, log);
        setIfPresent(options, "Function ID", false, log);
        setIfPresent(options, "Embedded Media", false, log);
        setIfPresent(options, "DWARF", false, log);
        setIfPresent(options, "Demangler GNU", false, log);
        setIfPresent(options, "Non-Returning Functions - Discovered", false, log);
        setIfPresent(options, "Call-Fixup Installer", false, log);
        setIfPresent(options, "Create Address Tables", false, log);

        setIfPresent(options, "ASCII Strings", true, log);
        setIfPresent(options, "Reference", true, log);
        setIfPresent(options, "Data Reference", true, log);
        setIfPresent(options, "Subroutine References", true, log);
        setIfPresent(options, "Basic Constant Reference Analyzer", true, log);
        setIfPresent(options, "Shared Return Calls", true, log);
        setIfPresent(options, "Function Start Search", true, log);
        log.accept("MTK_DIFF_ANALYSIS_CONFIGURED");
    }

    private static void setIfPresent(Options options, String name, boolean value,
            Consumer<String> log) {
        if (options.contains(name)) {
            options.setBoolean(name, value);
            log.accept("MTK_DIFF_ANALYSIS_OPTION " + name + "=" + value);
        }
    }
}
