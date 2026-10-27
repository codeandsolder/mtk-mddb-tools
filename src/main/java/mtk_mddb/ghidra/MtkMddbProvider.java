package mtk_mddb.ghidra;

import java.awt.BorderLayout;
import java.awt.FlowLayout;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.File;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.JTextField;
import javax.swing.SwingWorker;
import javax.swing.table.DefaultTableModel;

import docking.ComponentProvider;
import docking.WindowPosition;
import docking.widgets.filechooser.GhidraFileChooser;
import docking.widgets.filechooser.GhidraFileChooserMode;
import ghidra.util.Msg;

final class MtkMddbProvider extends ComponentProvider {
    private static final int SEARCH_LIMIT = 500;
    private static final int CONTEXT = 96;

    private final MtkMddbPlugin plugin;
    private final JPanel panel = new JPanel(new BorderLayout(6, 6));
    private final JLabel sourceLabel = new JLabel("No MDDB loaded");
    private final JLabel statusLabel = new JLabel(" ");
    private final JTextField searchField = new JTextField(36);
    private final JComboBox<String> columnFamily = new JComboBox<>(new String[] {"All"});
    private final DefaultTableModel model;
    private final JTable table;
    private volatile MddbDatabase database;
    private volatile List<DisplayResult> displayedResults = List.of();
    private record DisplayResult(MddbSearchResult match, String schema) {}

    MtkMddbProvider(MtkMddbPlugin plugin) {
        super(plugin.getTool(), "MediaTek MDDB", plugin.getName());
        this.plugin = plugin;
        model = new DefaultTableModel(new Object[] {"CF", "Field", "Key", "Offset", "Schema", "Context"}, 0) {
            @Override
            public boolean isCellEditable(int row, int column) {
                return false;
            }
        };
        table = new JTable(model);
        buildUi();
        setDefaultWindowPosition(WindowPosition.BOTTOM);
        setTabText("MediaTek MDDB");
    }

    private void buildUi() {
        JPanel source = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JButton open = new JButton("Open EDB...");
        open.addActionListener(e -> chooseAndOpen());
        source.add(open);
        source.add(sourceLabel);

        JPanel search = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JButton searchButton = new JButton("Search");
        searchButton.addActionListener(e -> runSearch());
        searchField.addActionListener(e -> runSearch());
        JButton find = new JButton("Find in Program");
        find.addActionListener(e -> findInProgram());
        JButton xref = new JButton("Go to Code Xref");
        xref.addActionListener(e -> goToCodeXref());
        JButton annotate = new JButton("Annotate Program");
        annotate.addActionListener(e -> annotateProgram());
        JButton importType = new JButton("Import MDDB Type");
        importType.addActionListener(e -> importSelectedType());
        search.add(new JLabel("Search:"));
        search.add(searchField);
        search.add(new JLabel("Column family:"));
        search.add(columnFamily);
        search.add(searchButton);
        search.add(find);
        search.add(xref);
        search.add(annotate);
        search.add(importType);

        JPanel north = new JPanel(new BorderLayout());
        north.add(source, BorderLayout.NORTH);
        north.add(search, BorderLayout.SOUTH);
        panel.add(north, BorderLayout.NORTH);
        panel.add(new JScrollPane(table), BorderLayout.CENTER);
        panel.add(statusLabel, BorderLayout.SOUTH);

        table.setAutoCreateRowSorter(true);
        table.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                if (e.getClickCount() == 2 && table.getSelectedRow() >= 0) {
                    findInProgram();
                }
            }
        });
    }

    void chooseAndOpen() {
        GhidraFileChooser chooser = new GhidraFileChooser(panel);
        chooser.setFileSelectionMode(GhidraFileChooserMode.FILES_AND_DIRECTORIES);
        chooser.setApproveButtonText("Open MDDB");
        File selected = chooser.getSelectedFile();
        chooser.dispose();
        if (selected != null) {
            open(selected.toPath());
        }
    }

    void open(Path path) {
        setVisible(true);
        statusLabel.setText("Opening " + path + " ...");
        new SwingWorker<MddbDatabase, Void>() {
            @Override
            protected MddbDatabase doInBackground() throws Exception {
                return MddbDatabase.open(path);
            }

            @Override
            protected void done() {
                try {
                    MddbDatabase opened = get();
                    MddbDatabase old = database;
                    database = opened;
                    if (old != null) {
                        old.close();
                    }
                    sourceLabel.setText(path.toString());
                    displayedResults = List.of();
                    model.setRowCount(0);
                    columnFamily.removeAllItems();
                    columnFamily.addItem("All");
                    for (String cf : opened.columnFamilies()) {
                        columnFamily.addItem(cf);
                    }
                    statusLabel.setText("Loaded " + opened.columnFamilies().size() +
                        " column families; DATAA " + opened.dataASize() + " bytes");
                } catch (Exception e) {
                    statusLabel.setText("Open failed: " + e.getMessage());
                    Msg.showError(this, panel, "MediaTek MDDB", "Failed to open " + path, e);
                }
            }
        }.execute();
    }

    private void runSearch() {
        MddbDatabase db = database;
        String needle = searchField.getText();
        String cf = (String) columnFamily.getSelectedItem();
        if (db == null) {
            statusLabel.setText("Open an EDB first.");
            return;
        }
        if (needle == null || needle.isEmpty()) {
            statusLabel.setText("Enter text to search for.");
            return;
        }
        statusLabel.setText("Searching...");
        new SwingWorker<List<DisplayResult>, Void>() {
            @Override
            protected List<DisplayResult> doInBackground() throws Exception {
                List<MddbSearchResult> matches = db.search(needle, cf, SEARCH_LIMIT);
                List<DisplayResult> enriched = new ArrayList<>(matches.size());
                for (MddbSearchResult match : matches) {
                    enriched.add(new DisplayResult(match, db.schemaInfo(match)));
                }
                return enriched;
            }

            @Override
            protected void done() {
                try {
                    List<DisplayResult> rows = get();
                    displayedResults = List.copyOf(rows);
                    model.setRowCount(0);
                    int needleLength = needle.getBytes(java.nio.charset.StandardCharsets.UTF_8).length;
                    for (DisplayResult row : rows) {
                        MddbSearchResult result = row.match();
                        model.addRow(new Object[] {
                            result.columnFamily(), result.field(), result.keyHex(),
                            String.format("0x%x", result.offset()),
                            row.schema(),
                            MddbDatabase.renderContext(result, CONTEXT, needleLength)
                        });
                    }
                    statusLabel.setText("Found " + rows.size() +
                        (rows.size() >= SEARCH_LIMIT ? " matches (limit reached)" : " matches"));
                } catch (Exception e) {
                    statusLabel.setText("Search failed: " + e.getMessage());
                    Msg.showError(this, panel, "MediaTek MDDB", "Search failed", e);
                }
            }
        }.execute();
    }

    private void findInProgram() {
        String text = searchField.getText();
        if (text != null && !text.isEmpty()) {
            plugin.findInProgram(text);
        }
    }

    private void goToCodeXref() {
        String text = searchField.getText();
        if (text != null && !text.isEmpty()) {
            plugin.goToCodeXref(text);
        }
    }

    private void annotateProgram() {
        String text = searchField.getText();
        if (text != null && !text.isEmpty()) {
            plugin.annotateInProgram(text);
        }
    }

    private void importSelectedType() {
        MddbDatabase db = database;
        if (db == null) {
            statusLabel.setText("Open an EDB first.");
            return;
        }
        int selected = table.getSelectedRow();
        if (selected < 0) {
            statusLabel.setText("Select a schema-bearing MDDB search result first.");
            return;
        }
        int modelRow = table.convertRowIndexToModel(selected);
        List<DisplayResult> rows = displayedResults;
        if (modelRow < 0 || modelRow >= rows.size()) {
            statusLabel.setText("Selected result is no longer available; search again.");
            return;
        }
        plugin.importDataType(db, rows.get(modelRow).match());
    }

    void disposeProvider() {
        MddbDatabase db = database;
        database = null;
        if (db != null) {
            try {
                db.close();
            } catch (Exception e) {
                Msg.error(this, "Failed to close MediaTek MDDB", e);
            }
        }
    }

    @Override
    public JComponent getComponent() {
        return panel;
    }
}
