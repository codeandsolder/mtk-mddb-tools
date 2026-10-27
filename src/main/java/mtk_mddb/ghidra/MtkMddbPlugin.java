package mtk_mddb.ghidra;

import java.nio.file.Path;
import java.util.List;

import javax.swing.SwingUtilities;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.task.Task;
import ghidra.util.task.TaskLauncher;
import ghidra.util.task.TaskMonitor;

@PluginInfo(
    status = PluginStatus.RELEASED,
    packageName = "MediaTek MDDB",
    category = PluginCategoryNames.ANALYSIS,
    shortDescription = "Browse MediaTek Catcher/META MDDB databases",
    description = "Opens MediaTek CATD .EDB modem databases, browses their embedded RocksDB, " +
        "and maps database strings back into the current Ghidra program."
)
public final class MtkMddbPlugin extends ProgramPlugin {
    private final MtkMddbProvider provider;

    public MtkMddbPlugin(PluginTool tool) {
        super(tool);
        provider = new MtkMddbProvider(this);
        provider.addToTool();
        installActions();
    }

    private void installActions() {
        DockingAction open = new DockingAction("Open MediaTek MDDB", getName()) {
            @Override
            public void actionPerformed(ActionContext context) {
                provider.chooseAndOpen();
            }
        };
        open.setMenuBarData(new MenuData(new String[] {"Tools", "MediaTek MDDB", "Open EDB..."}));
        tool.addAction(open);

        DockingAction show = new DockingAction("Show MediaTek MDDB", getName()) {
            @Override
            public void actionPerformed(ActionContext context) {
                provider.setVisible(true);
                provider.toFront();
            }
        };
        show.setMenuBarData(new MenuData(new String[] {"Tools", "MediaTek MDDB", "Show Browser"}));
        tool.addAction(show);
    }

    void openDatabase(Path path) {
        provider.open(path);
    }

    void findInProgram(String text) {
        Program program = currentProgram;
        if (program == null) {
            Msg.showWarn(this, provider.getComponent(), "MediaTek MDDB", "Open a program first.");
            return;
        }
        Task task = new Task("Find MDDB text in program", true, true, true) {
            @Override
            public void run(TaskMonitor monitor) {
                try {
                    List<Address> hits = ProgramAnnotator.findAscii(program, text, monitor);
                    if (hits.isEmpty()) {
                        Msg.showInfo(this, provider.getComponent(), "MediaTek MDDB",
                            "No program bytes matched: " + text);
                        return;
                    }
                    SwingUtilities.invokeLater(() -> goTo(hits.get(0)));
                } catch (Exception e) {
                    Msg.showError(this, provider.getComponent(), "MediaTek MDDB", "Program search failed", e);
                }
            }
        };
        new TaskLauncher(task, provider.getComponent());
    }

    void goToCodeXref(String text) {
        Program program = currentProgram;
        if (program == null) {
            Msg.showWarn(this, provider.getComponent(), "MediaTek MDDB", "Open a program first.");
            return;
        }
        Task task = new Task("Find MDDB code xref", true, true, true) {
            @Override
            public void run(TaskMonitor monitor) {
                try {
                    List<Address> refs = ProgramAnnotator.findCodeReferences(program, text, monitor);
                    if (refs.isEmpty()) {
                        Msg.showInfo(this, provider.getComponent(), "MediaTek MDDB",
                            "No code references found for: " + text);
                        return;
                    }
                    SwingUtilities.invokeLater(() -> goTo(refs.get(0)));
                } catch (Exception e) {
                    Msg.showError(this, provider.getComponent(), "MediaTek MDDB", "Code xref search failed", e);
                }
            }
        };
        new TaskLauncher(task, provider.getComponent());
    }

    void importDataType(MddbDatabase database, MddbSearchResult result) {
        Program program = currentProgram;
        if (program == null) {
            Msg.showWarn(this, provider.getComponent(), "MediaTek MDDB", "Open a program first.");
            return;
        }
        Task task = new Task("Import MDDB data type", true, true, true) {
            @Override
            public void run(TaskMonitor monitor) {
                try {
                    MddbTypeImporter.ImportSummary summary =
                        MddbTypeImporter.importSelection(program, database, result, monitor);
                    if (summary.imported().isEmpty()) {
                        Msg.showInfo(this, provider.getComponent(), "MediaTek MDDB",
                            "The selected MDDB result does not resolve to a decoded type or enum.");
                    } else {
                        Msg.showInfo(this, provider.getComponent(), "MediaTek MDDB",
                            "Imported into the program data-type manager:\n" +
                                String.join("\n", summary.imported()));
                    }
                } catch (Exception e) {
                    Msg.showError(this, provider.getComponent(), "MediaTek MDDB",
                        "Data-type import failed", e);
                }
            }
        };
        new TaskLauncher(task, provider.getComponent());
    }

    void annotateInProgram(String text) {
        Program program = currentProgram;
        if (program == null) {
            Msg.showWarn(this, provider.getComponent(), "MediaTek MDDB", "Open a program first.");
            return;
        }
        Task task = new Task("Annotate MDDB matches", true, true, true) {
            @Override
            public void run(TaskMonitor monitor) {
                try {
                    ProgramAnnotator.AnnotationSummary summary = ProgramAnnotator.annotate(program, text, monitor);
                    String message;
                    if (summary.stringMatches() == 0) {
                        message = "No program bytes matched: " + text;
                    } else {
                        message = "Annotated " + summary.stringMatches() + " string occurrence(s) and " +
                            summary.codeReferences() + " code reference(s).";
                        if (!summary.functions().isEmpty()) {
                            message += "\nFunctions:\n" +
                                String.join("\n", summary.functions().stream().limit(12).toList());
                        }
                    }
                    Msg.showInfo(this, provider.getComponent(), "MediaTek MDDB", message);
                } catch (Exception e) {
                    Msg.showError(this, provider.getComponent(), "MediaTek MDDB", "Annotation failed", e);
                }
            }
        };
        new TaskLauncher(task, provider.getComponent());
    }

    @Override
    protected void cleanup() {
        provider.disposeProvider();
        provider.removeFromTool();
        super.cleanup();
    }
}
