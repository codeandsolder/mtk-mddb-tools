// Configure auto-analysis for reproducible MediaTek cross-build comparison.
//@category MediaTek

import ghidra.app.script.GhidraScript;
import mtk_mddb.ghidra.MtkDiffAnalysisRunner;

public class MtkDiffAnalysis extends GhidraScript {
    @Override
    protected void run() throws Exception {
        if (currentProgram == null) {
            throw new IllegalStateException("Open or import a MediaTek modem program first");
        }
        MtkDiffAnalysisRunner.configure(currentProgram, this::println);
    }
}
