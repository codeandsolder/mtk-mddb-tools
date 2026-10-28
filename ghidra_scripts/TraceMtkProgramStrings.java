// Trace selected modem/debug vocabulary from raw firmware strings into code xrefs and one-hop call graph.
//@category MediaTek

import java.io.File;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.List;

import ghidra.app.script.GhidraScript;
import mtk_mddb.ghidra.TraceMtkProgramStringsRunner;

public class TraceMtkProgramStrings extends GhidraScript {
    @Override
    protected void run() throws Exception {
        if (currentProgram == null) {
            throw new IllegalStateException("Open or process a MediaTek modem program first");
        }

        String[] args = getScriptArgs();
        Path output;
        List<String> needles;
        if (args.length >= 2) {
            output = Path.of(args[0]);
            needles = Arrays.asList(args).subList(1, args.length);
        } else {
            File selected = askFile("Choose MediaTek string-trace TSV", "Save");
            output = selected.toPath();
            String text = askString("MediaTek string trace",
                "Comma-separated case-insensitive substrings");
            needles = Arrays.asList(text.split(","));
        }
        TraceMtkProgramStringsRunner.run(currentProgram, monitor, output, needles, this::println);
    }
}
