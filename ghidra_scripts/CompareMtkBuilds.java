// Compare two analyzed MediaTek modem programs using their MDDBs as semantic anchors.
//@category MediaTek

import java.io.File;
import java.nio.file.Path;

import ghidra.app.script.GhidraScript;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainObject;
import ghidra.program.model.listing.Program;
import mtk_mddb.ghidra.CompareMtkBuildsRunner;

public class CompareMtkBuilds extends GhidraScript {
    @Override
    protected void run() throws Exception {
        if (currentProgram == null) {
            throw new IllegalStateException("Open or import the source modem program first");
        }

        String[] args = getScriptArgs();
        Program target = null;
        boolean releaseTarget = false;
        Path sourceEdb;
        Path targetEdb;
        Path output;
        boolean withBsim;
        boolean withVersionTracking;

        if (args.length >= 4) {
            DomainFile targetFile = parseDomainFile(args[0]);
            if (targetFile == null) {
                throw new IllegalArgumentException("Target project program not found: " + args[0]);
            }
            DomainObject domainObject = targetFile.getDomainObject(this, false, false, monitor);
            if (!(domainObject instanceof Program program)) {
                domainObject.release(this);
                throw new IllegalArgumentException("Target is not a Ghidra program: " + args[0]);
            }
            target = program;
            releaseTarget = true;
            sourceEdb = Path.of(args[1]);
            targetEdb = Path.of(args[2]);
            output = Path.of(args[3]);
            withBsim = false;
            withVersionTracking = false;
            for (int i = 4; i < args.length; i++) {
                withBsim |= args[i].equals("--bsim");
                withVersionTracking |= args[i].equals("--vt");
            }
        } else {
            target = askProgram("Select target MediaTek build");
            if (target == null) {
                return;
            }
            releaseTarget = true;
            File left = askFile("Select source MDDB EDB", "Open");
            File right = askFile("Select target MDDB EDB", "Open");
            File out = askFile("Choose comparison TSV", "Save");
            sourceEdb = left.toPath();
            targetEdb = right.toPath();
            output = out.toPath();
            withVersionTracking = askYesNo("MediaTek cross-build diff",
                "Run Ghidra Version Tracking correlators without applying markup?");
            withBsim = askYesNo("MediaTek cross-build diff",
                "Run BSim on the MDDB-anchored function pairs that Ghidra can decompile?");
        }

        try {
            CompareMtkBuildsRunner.run(currentProgram, target, sourceEdb, targetEdb, output,
                withBsim, withVersionTracking, monitor, this::println);
        } finally {
            if (releaseTarget && target != null) {
                target.release(this);
            }
        }
    }
}
