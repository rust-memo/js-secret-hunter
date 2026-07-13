package com.adminsec.jssecrethunter;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.RequestOptions;
import burp.api.montoya.http.RedirectionMode;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.ui.editor.EditorOptions;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.ui.editor.HttpResponseEditor;
import com.adminsec.jssecrethunter.RulePackManager.LoadedRulePack;
import com.adminsec.jssecrethunter.model.AssetRecord;
import com.adminsec.jssecrethunter.model.Finding;
import com.adminsec.jssecrethunter.model.ReviewStatus;

import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSpinner;
import javax.swing.JSplitPane;
import javax.swing.JTabbedPane;
import javax.swing.JTable;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.RowFilter;
import javax.swing.SpinnerNumberModel;
import javax.swing.SwingWorker;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.TableRowSorter;
import java.awt.BorderLayout;
import java.awt.FlowLayout;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.Toolkit;
import java.awt.datatransfer.StringSelection;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.function.Consumer;
import java.util.concurrent.ExecutionException;

public final class HunterPanel extends JPanel {
    private final MontoyaApi api;
    private final HunterConfig config;
    private final HunterRepository repository;
    private final RulePackManager rules;
    private final ScannerService scanner;
    private final Consumer<LoadedRulePack> persistRules;
    private final FindingModel findingModel = new FindingModel();
    private final AssetModel assetModel = new AssetModel();
    private final JTable findingTable = new JTable(findingModel);
    private final JTable assetTable = new JTable(assetModel);
    private final TableRowSorter<FindingModel> sorter = new TableRowSorter<>(findingModel);
    private final JTextField search = new JTextField(24);
    private final JComboBox<String> severity = new JComboBox<>(new String[]{"All severities", "CRITICAL", "HIGH", "MEDIUM", "INFO"});
    private final JComboBox<String> kind = new JComboBox<>(new String[]{"All kinds", "SECRET", "CREDENTIAL", "ENDPOINT", "IDENTIFIER", "CONFIGURATION"});
    private final HttpRequestEditor requestEditor;
    private final HttpResponseEditor responseEditor;
    private final JTextArea details = new JTextArea(4, 80);
    private final JLabel ruleInfo = new JLabel();
    private final JCheckBox autoFetch = new JCheckBox("Fetch missing assets automatically (Target Scope only)");
    private final JSpinner maxDepth = new JSpinner(new SpinnerNumberModel(3, 0, 10, 1));
    private final JSpinner maxAssets = new JSpinner(new SpinnerNumberModel(500, 1, 10000, 10));
    private final JSpinner maxJsMb = new JSpinner(new SpinnerNumberModel(5, 1, 100, 1));
    private final JSpinner maxMapMb = new JSpinner(new SpinnerNumberModel(10, 1, 200, 1));
    private final JSpinner timeout = new JSpinner(new SpinnerNumberModel(15, 3, 120, 1));
    private final JSpinner perHost = new JSpinner(new SpinnerNumberModel(2, 1, 8, 1));

    public HunterPanel(MontoyaApi api, HunterConfig config, HunterRepository repository, RulePackManager rules,
                       ScannerService scanner, Consumer<LoadedRulePack> persistRules) {
        super(new BorderLayout());
        this.api = api; this.config = config; this.repository = repository; this.rules = rules;
        this.scanner = scanner; this.persistRules = persistRules;
        requestEditor = api.userInterface().createHttpRequestEditor(EditorOptions.READ_ONLY);
        responseEditor = api.userInterface().createHttpResponseEditor(EditorOptions.READ_ONLY);
        build(); loadSettings(); updateRuleInfo();
        repository.listener(snapshot -> { findingModel.replace(snapshot.findings()); assetModel.replace(snapshot.assets()); applyFilter(); });
        HunterRepository.Snapshot snapshot = repository.snapshot();
        findingModel.replace(snapshot.findings()); assetModel.replace(snapshot.assets());
    }

    private void build() {
        JTabbedPane tabs = new JTabbedPane();
        tabs.addTab("Findings", findingsTab()); tabs.addTab("Assets", assetsTab());
        tabs.addTab("Rules", rulesTab()); tabs.addTab("Settings", settingsTab());
        add(tabs, BorderLayout.CENTER); api.userInterface().applyThemeToComponent(this);
    }

    private JPanel findingsTab() {
        JPanel panel = new JPanel(new BorderLayout());
        JPanel top = new JPanel(new FlowLayout(FlowLayout.LEFT));
        top.add(new JLabel("Search:")); top.add(search); top.add(severity); top.add(kind);
        addButton(top, "Rescan History", this::rescan);
        addButton(top, "Pause/Resume", () -> { if (scanner.paused()) scanner.resume(); else scanner.pause(); });
        addButton(top, "Cancel queued", scanner::cancelQueued);
        addButton(top, "Clear", scanner::clearScanState);
        search.getDocument().addDocumentListener((DocumentChange) e -> applyFilter());
        severity.addActionListener(e -> applyFilter()); kind.addActionListener(e -> applyFilter());

        findingTable.setRowSorter(sorter); findingTable.setAutoResizeMode(JTable.AUTO_RESIZE_OFF);
        int[] widths = {70, 85, 105, 210, 170, 55, 480, 110};
        for (int i = 0; i < widths.length; i++) findingTable.getColumnModel().getColumn(i).setPreferredWidth(widths[i]);
        findingTable.getSelectionModel().addListSelectionListener(e -> showFinding());
        details.setEditable(false); details.setLineWrap(true); details.setWrapStyleWord(true);
        JTabbedPane lower = new JTabbedPane();
        lower.addTab("Request", requestEditor.uiComponent()); lower.addTab("Response", responseEditor.uiComponent());
        lower.addTab("Evidence", new JScrollPane(details));
        JSplitPane split = new JSplitPane(JSplitPane.VERTICAL_SPLIT, new JScrollPane(findingTable), lower);
        split.setResizeWeight(.55);

        JPanel actions = new JPanel(new FlowLayout(FlowLayout.LEFT));
        addButton(actions, "Reveal", this::reveal); addButton(actions, "Copy value", this::copyValue);
        addButton(actions, "Send to Repeater", this::sendToRepeater);
        addButton(actions, "Reviewed", () -> status(ReviewStatus.REVIEWED));
        addButton(actions, "False positive", () -> status(ReviewStatus.FALSE_POSITIVE));
        addButton(actions, "Needs review", () -> status(ReviewStatus.NEEDS_REVIEW));
        addButton(actions, "Ignore rule", this::ignoreRule); addButton(actions, "Ignore host", this::ignoreHost);
        addButton(actions, "Export JSON", () -> export(false, false)); addButton(actions, "Export CSV", () -> export(true, false));
        addButton(actions, "Export full…", () -> export(false, true));

        panel.add(top, BorderLayout.NORTH); panel.add(split, BorderLayout.CENTER); panel.add(actions, BorderLayout.SOUTH);
        return panel;
    }

    private JPanel assetsTab() {
        JPanel panel = new JPanel(new BorderLayout()); assetTable.setAutoResizeMode(JTable.AUTO_RESIZE_OFF);
        int[] widths = {95, 55, 470, 400, 160};
        for (int i = 0; i < widths.length; i++) assetTable.getColumnModel().getColumn(i).setPreferredWidth(widths[i]);
        JPanel top = new JPanel(new FlowLayout(FlowLayout.LEFT));
        top.add(new JLabel("Background assets are fetched only when every URL is in Target Scope."));
        panel.add(top, BorderLayout.NORTH); panel.add(new JScrollPane(assetTable), BorderLayout.CENTER); return panel;
    }

    private JPanel rulesTab() {
        JPanel panel = new JPanel(new BorderLayout());
        JPanel top = new JPanel(new FlowLayout(FlowLayout.LEFT)); top.add(ruleInfo);
        JPanel buttons = new JPanel(new FlowLayout(FlowLayout.LEFT));
        addButton(buttons, "Import JSON file…", this::importRulesFile);
        addButton(buttons, "Import from URL…", this::importRulesUrl);
        addButton(buttons, "Restore bundled rules", () -> {
            rules.restoreBundled(); persistRules.accept(rules.current()); updateRuleInfo(); rescanAfterRuleChange();
        });
        addButton(buttons, "Restore ignored rules/hosts", repository::restoreIgnores);
        JTextArea help = new JTextArea("Rule packs use schemaVersion 1 and RE2-compatible expressions.\n"
                + "Imports are validated completely before the active pack is replaced. URL imports happen only after you click the button.\n"
                + "Raw findings are never sent to the rule source or any verification service.");
        help.setEditable(false); help.setBorder(BorderFactory.createEmptyBorder(12, 12, 12, 12));
        panel.add(top, BorderLayout.NORTH); panel.add(help, BorderLayout.CENTER); panel.add(buttons, BorderLayout.SOUTH); return panel;
    }

    private JPanel settingsTab() {
        JPanel panel = new JPanel(new GridBagLayout()); panel.setBorder(BorderFactory.createEmptyBorder(12, 12, 12, 12));
        GridBagConstraints c = new GridBagConstraints(); c.insets = new Insets(6, 6, 6, 6); c.anchor = GridBagConstraints.WEST;
        c.gridx = 0; c.gridy = 0; c.gridwidth = 2; panel.add(autoFetch, c); c.gridwidth = 1;
        addSetting(panel, c, "Maximum discovery depth:", maxDepth);
        addSetting(panel, c, "Maximum assets per root:", maxAssets);
        addSetting(panel, c, "Maximum JavaScript size (MB):", maxJsMb);
        addSetting(panel, c, "Maximum source-map size (MB):", maxMapMb);
        addSetting(panel, c, "Request timeout (seconds):", timeout);
        addSetting(panel, c, "Concurrent requests per host:", perHost);
        JPanel actions = new JPanel(new FlowLayout(FlowLayout.LEFT)); addButton(actions, "Apply and rescan", this::applySettings);
        c.gridx = 0; c.gridy++; c.gridwidth = 2; panel.add(actions, c);
        c.gridy++; panel.add(new JLabel("Automatic fetching always enforces Burp Target Scope and a maximum of 3 redirects."), c);
        c.weighty = 1; c.gridy++; panel.add(new JPanel(), c); return panel;
    }

    private void addSetting(JPanel panel, GridBagConstraints c, String label, JSpinner spinner) {
        c.gridy++; c.gridx = 0; panel.add(new JLabel(label), c); c.gridx = 1; panel.add(spinner, c);
    }

    private void loadSettings() {
        autoFetch.setSelected(config.autoFetch()); maxDepth.setValue(config.maxDepth()); maxAssets.setValue(config.maxAssetsPerRoot());
        maxJsMb.setValue(config.maxJsBytes() / 1024 / 1024); maxMapMb.setValue(config.maxMapBytes() / 1024 / 1024);
        timeout.setValue(config.timeoutSeconds()); perHost.setValue(config.perHost());
    }

    private void applySettings() {
        config.autoFetch(autoFetch.isSelected()); config.maxDepth((Integer) maxDepth.getValue());
        config.maxAssetsPerRoot((Integer) maxAssets.getValue()); config.maxJsBytes((Integer) maxJsMb.getValue() * 1024 * 1024);
        config.maxMapBytes((Integer) maxMapMb.getValue() * 1024 * 1024); config.timeoutSeconds((Integer) timeout.getValue());
        config.perHost((Integer) perHost.getValue()); config.save(api.persistence().preferences());
        scanner.clearScanState(); scanner.scanHistory();
    }

    private void showFinding() {
        Finding f = selected(); if (f == null) return;
        requestEditor.setRequest(f.request()); if (f.response() != null) responseEditor.setResponse(f.response());
        if (!f.rawValue().isBlank()) responseEditor.setSearchExpression(f.rawValue());
        details.setText("Rule: " + f.ruleName() + " (" + f.ruleId() + ")\nValue: " + f.maskedValue()
                + "\nSHA-256: " + f.valueFingerprint() + "\nLine: " + f.line() + "\nChain: "
                + String.join(" -> ", f.discoveryChain()) + "\nEvidence: " + f.preview());
    }

    private Finding selected() {
        int row = findingTable.getSelectedRow(); return row < 0 ? null : findingModel.get(sorter.convertRowIndexToModel(row));
    }

    private void reveal() {
        Finding f = selected(); if (f == null) return;
        int answer = JOptionPane.showConfirmDialog(api.userInterface().swingUtils().suiteFrame(),
                "Reveal the raw value on screen? Avoid screenshots and shared sessions.", "Reveal sensitive value", JOptionPane.OK_CANCEL_OPTION);
        if (answer == JOptionPane.OK_OPTION) JOptionPane.showMessageDialog(api.userInterface().swingUtils().suiteFrame(), f.rawValue(), "Raw value", JOptionPane.WARNING_MESSAGE);
    }

    private void copyValue() {
        Finding f = selected(); if (f == null) return;
        int answer = JOptionPane.showConfirmDialog(api.userInterface().swingUtils().suiteFrame(), "Copy the raw value to the system clipboard?",
                "Copy sensitive value", JOptionPane.OK_CANCEL_OPTION);
        if (answer == JOptionPane.OK_OPTION) Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(f.rawValue()), null);
    }

    private void sendToRepeater() { Finding f = selected(); if (f != null) api.repeater().sendToRepeater(f.request(), "JS asset - " + host(f.assetUrl())); }
    private void status(ReviewStatus status) { Finding f = selected(); if (f != null) repository.setStatus(f, status); }
    private void ignoreRule() { Finding f = selected(); if (f != null) repository.ignoreRule(f.ruleId()); }
    private void ignoreHost() { Finding f = selected(); if (f != null) repository.ignoreHost(host(f.assetUrl())); }

    private void applyFilter() {
        String query = search.getText().trim().toLowerCase(Locale.ROOT);
        String selectedSeverity = (String) severity.getSelectedItem(), selectedKind = (String) kind.getSelectedItem();
        sorter.setRowFilter(new RowFilter<>() {
            public boolean include(Entry<? extends FindingModel, ? extends Integer> entry) {
                Finding f = findingModel.get(entry.getIdentifier());
                boolean severityOk = "All severities".equals(selectedSeverity) || f.severity().name().equals(selectedSeverity);
                boolean kindOk = "All kinds".equals(selectedKind) || f.kind().name().equals(selectedKind);
                String haystack = (f.ruleName() + " " + f.assetUrl() + " " + f.maskedValue() + " " + f.preview()).toLowerCase(Locale.ROOT);
                return severityOk && kindOk && (query.isBlank() || haystack.contains(query));
            }
        });
    }

    private void export(boolean csv, boolean full) {
        if (full) {
            int answer = JOptionPane.showConfirmDialog(api.userInterface().swingUtils().suiteFrame(),
                    "This export will contain raw credentials. Continue?", "Unredacted export", JOptionPane.OK_CANCEL_OPTION, JOptionPane.WARNING_MESSAGE);
            if (answer != JOptionPane.OK_OPTION) return;
        }
        JFileChooser chooser = new JFileChooser();
        if (chooser.showSaveDialog(api.userInterface().swingUtils().suiteFrame()) != JFileChooser.APPROVE_OPTION) return;
        Path path = chooser.getSelectedFile().toPath();
        try { Files.writeString(path, csv ? HunterExporter.csv(repository.snapshot().findings(), full)
                : HunterExporter.json(repository.snapshot().findings(), full), StandardCharsets.UTF_8); }
        catch (IOException error) { showError("Export failed", error); }
    }

    private void importRulesFile() {
        JFileChooser chooser = new JFileChooser();
        if (chooser.showOpenDialog(api.userInterface().swingUtils().suiteFrame()) != JFileChooser.APPROVE_OPTION) return;
        try {
            Path path = chooser.getSelectedFile().toPath();
            if (Files.size(path) > 5 * 1024 * 1024) throw new IllegalArgumentException("Rule pack exceeds 5 MB");
            confirmAndApply(rules.validate(Files.readAllBytes(path)));
        }
        catch (IOException | IllegalArgumentException error) { showError("Rule import failed", error); }
    }

    private void importRulesUrl() {
        String url = JOptionPane.showInputDialog(api.userInterface().swingUtils().suiteFrame(), "HTTPS URL for a schemaVersion 1 rule pack:", "Import rules", JOptionPane.PLAIN_MESSAGE);
        if (url == null || url.isBlank()) return;
        if (!url.toLowerCase(Locale.ROOT).startsWith("https://")) { showError("Rule import failed", new IllegalArgumentException("Only HTTPS rule-pack URLs are accepted")); return; }
        new SwingWorker<LoadedRulePack, Void>() {
            @Override protected LoadedRulePack doInBackground() {
                HttpRequestResponse rr = api.http().sendRequest(HttpRequest.httpRequestFromUrl(url.trim()), RequestOptions.requestOptions()
                        .withRedirectionMode(RedirectionMode.NEVER).withResponseTimeout(15_000));
                if (rr == null || !rr.hasResponse() || rr.response().statusCode() < 200 || rr.response().statusCode() >= 300) {
                    throw new IllegalArgumentException("Rule server did not return a 2xx response");
                }
                if (rr.response().body().length() > 5 * 1024 * 1024) throw new IllegalArgumentException("Rule pack exceeds 5 MB");
                return rules.validate(rr.response().body().getBytes());
            }
            @Override protected void done() {
                try { confirmAndApply(get()); }
                catch (InterruptedException error) { Thread.currentThread().interrupt(); }
                catch (ExecutionException error) { showError("Rule import failed", error.getCause() == null ? error : error.getCause()); }
            }
        }.execute();
    }

    private void confirmAndApply(LoadedRulePack pack) {
        int answer = JOptionPane.showConfirmDialog(api.userInterface().swingUtils().suiteFrame(),
                "Version: " + pack.version() + "\nReleased: " + pack.releasedAt() + "\nRules: " + pack.rules().size()
                        + "\nSHA-256: " + pack.sha256() + "\n\nApply this pack?",
                "Validated rule pack", JOptionPane.OK_CANCEL_OPTION);
        if (answer != JOptionPane.OK_OPTION) return;
        rules.apply(pack); persistRules.accept(pack); updateRuleInfo(); rescanAfterRuleChange();
    }

    private void rescanAfterRuleChange() { scanner.clearScanState(); scanner.scanHistory(); }
    private void rescan() { scanner.clearScanState(); scanner.scanHistory(); }
    private void updateRuleInfo() {
        LoadedRulePack p = rules.current(); ruleInfo.setText("Active pack: " + p.version() + " | " + p.rules().size() + " rules | SHA-256 " + p.shortHash() + "…");
    }
    private void showError(String title, Throwable error) {
        JOptionPane.showMessageDialog(api.userInterface().swingUtils().suiteFrame(), error.getMessage(), title, JOptionPane.ERROR_MESSAGE);
    }
    private static String host(String url) {
        try { String host = java.net.URI.create(url).getHost(); return host == null ? "asset" : host; }
        catch (RuntimeException error) { return "asset"; }
    }
    private static void addButton(JPanel panel, String label, Runnable action) { JButton b = new JButton(label); b.addActionListener(e -> action.run()); panel.add(b); }

    private static final class FindingModel extends AbstractTableModel {
        private final String[] columns = {"Severity", "Confidence", "Kind", "Rule", "Value", "Line", "Asset URL", "Status"};
        private List<Finding> rows = new ArrayList<>();
        void replace(List<Finding> values) { rows = new ArrayList<>(values); fireTableDataChanged(); }
        Finding get(int row) { return rows.get(row); }
        public int getRowCount() { return rows.size(); } public int getColumnCount() { return columns.length; }
        public String getColumnName(int column) { return columns[column]; }
        public Object getValueAt(int row, int column) { Finding f = rows.get(row); return switch (column) {
            case 0 -> f.severity(); case 1 -> f.confidence(); case 2 -> f.kind(); case 3 -> f.ruleName();
            case 4 -> f.maskedValue(); case 5 -> f.line(); case 6 -> f.assetUrl(); default -> f.reviewStatus(); }; }
    }

    private static final class AssetModel extends AbstractTableModel {
        private final String[] columns = {"Status", "Depth", "URL", "Parent", "Detail"};
        private List<AssetRecord> rows = new ArrayList<>();
        void replace(List<AssetRecord> values) { rows = new ArrayList<>(values); fireTableDataChanged(); }
        public int getRowCount() { return rows.size(); } public int getColumnCount() { return columns.length; }
        public String getColumnName(int column) { return columns[column]; }
        public Object getValueAt(int row, int column) { AssetRecord a = rows.get(row); return switch (column) {
            case 0 -> a.status(); case 1 -> a.depth(); case 2 -> a.url(); case 3 -> a.parentUrl(); default -> a.detail(); }; }
    }

    @FunctionalInterface private interface DocumentChange extends javax.swing.event.DocumentListener {
        void update(javax.swing.event.DocumentEvent event);
        default void insertUpdate(javax.swing.event.DocumentEvent e) { update(e); }
        default void removeUpdate(javax.swing.event.DocumentEvent e) { update(e); }
        default void changedUpdate(javax.swing.event.DocumentEvent e) { update(e); }
    }
}
