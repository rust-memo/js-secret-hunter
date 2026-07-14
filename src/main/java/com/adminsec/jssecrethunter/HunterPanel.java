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
import javax.swing.BoxLayout;
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
import java.awt.GridLayout;
import java.awt.Insets;
import java.awt.Toolkit;
import java.awt.datatransfer.StringSelection;
import java.awt.event.ComponentAdapter;
import java.awt.event.ComponentEvent;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.ExecutionException;
import java.util.function.Consumer;

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
    private final JTextField search = new JTextField(22);
    private final JComboBox<String> severity = new JComboBox<>(new String[]{"All severities", "CRITICAL", "HIGH", "MEDIUM", "INFO"});
    private final JComboBox<String> confidence = new JComboBox<>(new String[]{"All confidences", "HIGH", "MEDIUM", "LOW"});
    private final JComboBox<String> kind = new JComboBox<>(new String[]{"All kinds", "SECRET", "CREDENTIAL", "ENDPOINT", "IDENTIFIER", "CONFIGURATION"});
    private final JComboBox<String> reviewStatus = new JComboBox<>(new String[]{"All statuses", "NEEDS_REVIEW", "REVIEWED", "FALSE_POSITIVE"});
    private final HttpRequestEditor requestEditor;
    private final HttpResponseEditor responseEditor;
    private final JTextArea details = new JTextArea(4, 80);
    private final JLabel ruleInfo = new JLabel();
    private final JLabel scanInfo = new JLabel("Idle");
    private final JCheckBox autoFetch = new JCheckBox("Fetch missing assets automatically (Target Scope only)");
    private final JCheckBox targetScopeOnly = new JCheckBox("Analyze Proxy traffic in Target Scope only");
    private final JSpinner maxDepth = new JSpinner(new SpinnerNumberModel(3, 0, 10, 1));
    private final JSpinner maxAssets = new JSpinner(new SpinnerNumberModel(500, 1, 10000, 10));
    private final JSpinner maxJsMb = new JSpinner(new SpinnerNumberModel(5, 1, 100, 1));
    private final JSpinner maxMapMb = new JSpinner(new SpinnerNumberModel(10, 1, 200, 1));
    private final JSpinner maxTextMb = new JSpinner(new SpinnerNumberModel(5, 1, 100, 1));
    private final JSpinner maxHistoryEntries = new JSpinner(new SpinnerNumberModel(10_000, 100, 100_000, 100));
    private final JSpinner maxFindings = new JSpinner(new SpinnerNumberModel(10_000, 100, 100_000, 100));
    private final JSpinner timeout = new JSpinner(new SpinnerNumberModel(15, 3, 120, 1));
    private final JSpinner perHost = new JSpinner(new SpinnerNumberModel(2, 1, 8, 1));
    private final List<JButton> selectionActions = new ArrayList<>();
    private JButton pauseButton;
    private JButton cancelButton;
    private JButton publishButton;
    private volatile ScanState lastScanState = new ScanState(ScanState.Phase.IDLE, 0, 0, 0, 0, "Idle");
    private volatile int droppedFindings;

    public HunterPanel(MontoyaApi api, HunterConfig config, HunterRepository repository, RulePackManager rules,
                       ScannerService scanner, Consumer<LoadedRulePack> persistRules) {
        super(new BorderLayout());
        this.api = api; this.config = config; this.repository = repository; this.rules = rules;
        this.scanner = scanner; this.persistRules = persistRules;
        requestEditor = api.userInterface().createHttpRequestEditor(EditorOptions.READ_ONLY);
        responseEditor = api.userInterface().createHttpResponseEditor(EditorOptions.READ_ONLY);
        build(); loadSettings(); updateRuleInfo(); updateSelectionActions();
        repository.listener(snapshot -> {
            findingModel.replace(snapshot.findings()); assetModel.replace(snapshot.assets());
            droppedFindings = snapshot.droppedFindings(); applyFilter(); updateSelectionActions(); updateScanInfo();
        });
        scanner.stateListener(state -> { lastScanState = state; updateScanInfo(); updateScannerButtons(); });
        HunterRepository.Snapshot snapshot = repository.snapshot();
        findingModel.replace(snapshot.findings()); assetModel.replace(snapshot.assets()); droppedFindings = snapshot.droppedFindings();
    }

    private void build() {
        JTabbedPane tabs = new JTabbedPane();
        tabs.addTab("Findings", findingsTab()); tabs.addTab("Assets", assetsTab());
        tabs.addTab("Rules", rulesTab()); tabs.addTab("Settings", settingsTab());
        add(tabs, BorderLayout.CENTER); api.userInterface().applyThemeToComponent(this);
    }

    private JPanel findingsTab() {
        JPanel panel = new JPanel(new BorderLayout());
        JPanel top = new JPanel(); top.setLayout(new BoxLayout(top, BoxLayout.Y_AXIS));
        JPanel filters = new JPanel(new FlowLayout(FlowLayout.LEFT));
        filters.add(new JLabel("Search:")); filters.add(search); filters.add(severity); filters.add(confidence); filters.add(kind); filters.add(reviewStatus);
        JPanel controls = new JPanel(new FlowLayout(FlowLayout.LEFT));
        addButton(controls, "Rescan History", this::rescan);
        pauseButton = addButton(controls, "Pause", () -> { if (scanner.paused()) scanner.resume(); else scanner.pause(); });
        cancelButton = addButton(controls, "Cancel queued", scanner::cancelQueued);
        addButton(controls, "Clear", scanner::clearScanState);
        top.add(filters); top.add(controls);
        search.getDocument().addDocumentListener((DocumentChange) e -> applyFilter());
        severity.addActionListener(e -> applyFilter()); confidence.addActionListener(e -> applyFilter());
        kind.addActionListener(e -> applyFilter()); reviewStatus.addActionListener(e -> applyFilter());

        findingTable.setRowSorter(sorter); findingTable.setAutoResizeMode(JTable.AUTO_RESIZE_OFF);
        int[] widths = {70, 85, 105, 210, 170, 55, 480, 110, 75};
        for (int i = 0; i < widths.length; i++) findingTable.getColumnModel().getColumn(i).setPreferredWidth(widths[i]);
        findingTable.getSelectionModel().addListSelectionListener(e -> { showFinding(); updateSelectionActions(); });
        details.setEditable(false); details.setLineWrap(true); details.setWrapStyleWord(true);
        JTabbedPane lower = new JTabbedPane();
        lower.addTab("Request", requestEditor.uiComponent()); lower.addTab("Response", responseEditor.uiComponent());
        lower.addTab("Evidence", new JScrollPane(details));
        JSplitPane split = new JSplitPane(JSplitPane.VERTICAL_SPLIT, new JScrollPane(findingTable), lower);
        split.setResizeWeight(.55);

        ResponsiveActionPanel actions = new ResponsiveActionPanel();
        addSelectionButton(actions, "Reveal", this::reveal, "Reveal the selected raw value after confirmation");
        addSelectionButton(actions, "Copy value", this::copyValue, "Copy the selected raw value after confirmation");
        addSelectionButton(actions, "Send to Repeater", this::sendToRepeater, "Send the selected asset request to Repeater");
        addSelectionButton(actions, "Reviewed", () -> status(ReviewStatus.REVIEWED), "Mark the selected finding as reviewed");
        addSelectionButton(actions, "False positive", () -> status(ReviewStatus.FALSE_POSITIVE), "Mark the selected finding as a false positive");
        addSelectionButton(actions, "Needs review", () -> status(ReviewStatus.NEEDS_REVIEW), "Return the selected finding to the review queue");
        addSelectionButton(actions, "Ignore rule", this::ignoreRule, "Ignore this rule and remove its current findings");
        addSelectionButton(actions, "Ignore host", this::ignoreHost, "Ignore findings from this host");
        publishButton = addSelectionButton(actions, "Add as Burp issue", this::publishIssue, "Publish a reviewed, redacted issue to Burp Site map");
        addButton(actions, "Export JSON", () -> export(false, false));
        addButton(actions, "Export CSV", () -> export(true, false));
        addButton(actions, "Export full…", () -> export(false, true));

        JPanel bottom = new JPanel(new BorderLayout());
        scanInfo.setBorder(BorderFactory.createEmptyBorder(3, 8, 3, 8));
        bottom.add(scanInfo, BorderLayout.NORTH); bottom.add(actions, BorderLayout.CENTER);
        panel.add(top, BorderLayout.NORTH); panel.add(split, BorderLayout.CENTER); panel.add(bottom, BorderLayout.SOUTH);
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
            rules.restoreBundled(); persistRules.accept(rules.current()); updateRuleInfo(); scanner.restartHistoryScan();
        });
        addButton(buttons, "Restore ignored rules/hosts", () -> {
            repository.restoreIgnores(); scanner.restartHistoryScan();
        });
        JTextArea help = new JTextArea("Rule packs use schemaVersion 1 and RE2-compatible expressions.\n"
                + "Imports are validated completely before the active pack is replaced. URL imports happen only after you click the button.\n"
                + "Raw findings are never sent to the rule source or any verification service.");
        help.setEditable(false); help.setBorder(BorderFactory.createEmptyBorder(12, 12, 12, 12));
        panel.add(top, BorderLayout.NORTH); panel.add(help, BorderLayout.CENTER); panel.add(buttons, BorderLayout.SOUTH); return panel;
    }

    private JPanel settingsTab() {
        JPanel panel = new JPanel(new GridBagLayout()); panel.setBorder(BorderFactory.createEmptyBorder(12, 12, 12, 12));
        GridBagConstraints c = new GridBagConstraints(); c.insets = new Insets(6, 6, 6, 6); c.anchor = GridBagConstraints.WEST;
        c.gridx = 0; c.gridy = 0; c.gridwidth = 2; panel.add(targetScopeOnly, c); c.gridy++; panel.add(autoFetch, c); c.gridwidth = 1;
        addSetting(panel, c, "Maximum discovery depth:", maxDepth);
        addSetting(panel, c, "Maximum assets per root:", maxAssets);
        addSetting(panel, c, "Maximum JavaScript size (MB):", maxJsMb);
        addSetting(panel, c, "Maximum source-map size (MB):", maxMapMb);
        addSetting(panel, c, "Maximum other text size (MB):", maxTextMb);
        addSetting(panel, c, "Maximum Proxy history entries:", maxHistoryEntries);
        addSetting(panel, c, "Maximum retained findings:", maxFindings);
        addSetting(panel, c, "Request timeout (seconds):", timeout);
        addSetting(panel, c, "Concurrent requests per host:", perHost);
        JPanel actions = new JPanel(new FlowLayout(FlowLayout.LEFT)); addButton(actions, "Apply and rescan", this::applySettings);
        c.gridx = 0; c.gridy++; c.gridwidth = 2; panel.add(actions, c);
        c.gridy++; panel.add(new JLabel("Manual out-of-scope scans are local-only. Automatic fetching always enforces Target Scope."), c);
        c.weighty = 1; c.gridy++; panel.add(new JPanel(), c); return panel;
    }

    private void addSetting(JPanel panel, GridBagConstraints c, String label, JSpinner spinner) {
        c.gridy++; c.gridx = 0; panel.add(new JLabel(label), c); c.gridx = 1; panel.add(spinner, c);
    }

    private void loadSettings() {
        targetScopeOnly.setSelected(config.scanScope() == ScanScope.TARGET_SCOPE); autoFetch.setSelected(config.autoFetch());
        maxDepth.setValue(config.maxDepth()); maxAssets.setValue(config.maxAssetsPerRoot());
        maxJsMb.setValue(config.maxJsBytes() / 1024 / 1024); maxMapMb.setValue(config.maxMapBytes() / 1024 / 1024);
        maxTextMb.setValue(config.maxTextBytes() / 1024 / 1024); maxHistoryEntries.setValue(config.maxHistoryEntries());
        maxFindings.setValue(config.maxFindings()); timeout.setValue(config.timeoutSeconds()); perHost.setValue(config.perHost());
    }

    private void applySettings() {
        config.scanScope(targetScopeOnly.isSelected() ? ScanScope.TARGET_SCOPE : ScanScope.ALL_TRAFFIC);
        config.autoFetch(autoFetch.isSelected()); config.maxDepth((Integer) maxDepth.getValue());
        config.maxAssetsPerRoot((Integer) maxAssets.getValue()); config.maxJsBytes((Integer) maxJsMb.getValue() * 1024 * 1024);
        config.maxMapBytes((Integer) maxMapMb.getValue() * 1024 * 1024); config.maxTextBytes((Integer) maxTextMb.getValue() * 1024 * 1024);
        config.maxHistoryEntries((Integer) maxHistoryEntries.getValue()); config.maxFindings((Integer) maxFindings.getValue());
        config.timeoutSeconds((Integer) timeout.getValue()); config.perHost((Integer) perHost.getValue());
        config.save(api.persistence().preferences()); repository.maxFindings(config.maxFindings()); scanner.reconfigure(); scanner.restartHistoryScan();
    }

    private void showFinding() {
        Finding f = selected();
        if (f == null) { details.setText(""); return; }
        requestEditor.setRequest(f.request()); if (f.response() != null) responseEditor.setResponse(f.response());
        if (!f.rawValue().isBlank()) responseEditor.setSearchExpression(f.rawValue());
        details.setText("Rule: " + f.ruleName() + " (" + f.ruleId() + ")\nValue: " + f.maskedValue()
                + "\nSHA-256: " + f.valueFingerprint() + "\nLine: " + f.line() + "\nChain: "
                + String.join(" -> ", f.discoveryChain()) + "\nEvidence: " + f.preview());
    }

    private Finding selected() {
        int row = findingTable.getSelectedRow();
        return row < 0 ? null : findingModel.get(findingTable.convertRowIndexToModel(row));
    }

    private void updateSelectionActions() {
        Finding finding = selected();
        for (JButton button : selectionActions) button.setEnabled(finding != null);
        if (publishButton != null) publishButton.setEnabled(finding != null && finding.reviewStatus() == ReviewStatus.REVIEWED && !finding.published());
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
        if (answer != JOptionPane.OK_OPTION) return;
        try { Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(f.rawValue()), null); }
        catch (RuntimeException error) { showError("Copy failed", error); }
    }

    private void sendToRepeater() { Finding f = selected(); if (f != null) api.repeater().sendToRepeater(f.request(), "JS asset - " + host(f.assetUrl())); }
    private void status(ReviewStatus status) { Finding f = selected(); if (f != null) repository.setStatus(f, status); }

    private void ignoreRule() {
        Finding f = selected(); if (f == null) return;
        int answer = JOptionPane.showConfirmDialog(api.userInterface().swingUtils().suiteFrame(),
                "Ignore rule '" + f.ruleName() + "' and remove its current findings?", "Ignore rule", JOptionPane.OK_CANCEL_OPTION);
        if (answer == JOptionPane.OK_OPTION) repository.ignoreRule(f.ruleId());
    }

    private void ignoreHost() {
        Finding f = selected(); if (f == null) return; String host = host(f.assetUrl());
        int answer = JOptionPane.showConfirmDialog(api.userInterface().swingUtils().suiteFrame(),
                "Ignore host '" + host + "' and remove its current findings?", "Ignore host", JOptionPane.OK_CANCEL_OPTION);
        if (answer == JOptionPane.OK_OPTION) repository.ignoreHost(host);
    }

    private void publishIssue() {
        Finding f = selected(); if (f == null || f.reviewStatus() != ReviewStatus.REVIEWED || f.published()) return;
        int answer = JOptionPane.showConfirmDialog(api.userInterface().swingUtils().suiteFrame(),
                "Add a redacted audit issue to Burp Site map? The raw candidate will not be included in the issue detail.",
                "Add as Burp issue", JOptionPane.OK_CANCEL_OPTION);
        if (answer != JOptionPane.OK_OPTION) return;
        try { BurpIntegration.publish(api, repository, f); }
        catch (RuntimeException error) { showError("Could not add Burp issue", error); }
    }

    private void applyFilter() {
        String query = search.getText().trim().toLowerCase(Locale.ROOT);
        String selectedSeverity = (String) severity.getSelectedItem();
        String selectedConfidence = (String) confidence.getSelectedItem();
        String selectedKind = (String) kind.getSelectedItem();
        String selectedStatus = (String) reviewStatus.getSelectedItem();
        sorter.setRowFilter(new RowFilter<>() {
            public boolean include(Entry<? extends FindingModel, ? extends Integer> entry) {
                Finding f = findingModel.get(entry.getIdentifier());
                boolean severityOk = "All severities".equals(selectedSeverity) || f.severity().name().equals(selectedSeverity);
                boolean confidenceOk = "All confidences".equals(selectedConfidence) || f.confidence().name().equals(selectedConfidence);
                boolean kindOk = "All kinds".equals(selectedKind) || f.kind().name().equals(selectedKind);
                boolean statusOk = "All statuses".equals(selectedStatus) || f.reviewStatus().name().equals(selectedStatus);
                String haystack = (f.ruleName() + " " + f.ruleId() + " " + f.assetUrl() + " " + host(f.assetUrl())
                        + " " + f.maskedValue() + " " + f.preview()).toLowerCase(Locale.ROOT);
                return severityOk && confidenceOk && kindOk && statusOk && (query.isBlank() || haystack.contains(query));
            }
        });
        updateScanInfo();
    }

    private void export(boolean csv, boolean full) {
        if (full) {
            int answer = JOptionPane.showConfirmDialog(api.userInterface().swingUtils().suiteFrame(),
                    "This export will contain raw credentials. Continue?", "Unredacted export", JOptionPane.OK_CANCEL_OPTION, JOptionPane.WARNING_MESSAGE);
            if (answer != JOptionPane.OK_OPTION) return;
        }
        Object[] choices = {"Current filtered view", "All findings", "Cancel"};
        int choice = JOptionPane.showOptionDialog(api.userInterface().swingUtils().suiteFrame(), "Which findings should be exported?",
                "Export scope", JOptionPane.DEFAULT_OPTION, JOptionPane.QUESTION_MESSAGE, null, choices, choices[0]);
        if (choice < 0 || choice == 2) return;
        List<Finding> values = choice == 0 ? visibleFindings() : repository.snapshot().findings();
        if (values.isEmpty()) {
            JOptionPane.showMessageDialog(api.userInterface().swingUtils().suiteFrame(), "There are no findings in the selected export scope.", "Nothing to export", JOptionPane.INFORMATION_MESSAGE);
            return;
        }
        JFileChooser chooser = new JFileChooser();
        if (chooser.showSaveDialog(api.userInterface().swingUtils().suiteFrame()) != JFileChooser.APPROVE_OPTION) return;
        String extension = csv ? ".csv" : ".json";
        Path path = chooser.getSelectedFile().toPath();
        if (!path.getFileName().toString().toLowerCase(Locale.ROOT).endsWith(extension)) path = path.resolveSibling(path.getFileName() + extension);
        try {
            Files.writeString(path, csv ? HunterExporter.csv(values, full) : HunterExporter.json(values, full), StandardCharsets.UTF_8);
            JOptionPane.showMessageDialog(api.userInterface().swingUtils().suiteFrame(), "Exported " + values.size() + " findings to:\n" + path,
                    "Export complete", JOptionPane.INFORMATION_MESSAGE);
        } catch (IOException | RuntimeException error) { showError("Export failed", error); }
    }

    private List<Finding> visibleFindings() {
        List<Finding> values = new ArrayList<>();
        for (int viewRow = 0; viewRow < findingTable.getRowCount(); viewRow++) {
            values.add(findingModel.get(findingTable.convertRowIndexToModel(viewRow)));
        }
        return values;
    }

    private void importRulesFile() {
        JFileChooser chooser = new JFileChooser();
        if (chooser.showOpenDialog(api.userInterface().swingUtils().suiteFrame()) != JFileChooser.APPROVE_OPTION) return;
        try {
            Path path = chooser.getSelectedFile().toPath();
            if (Files.size(path) > 5 * 1024 * 1024) throw new IllegalArgumentException("Rule pack exceeds 5 MB");
            confirmAndApply(rules.validate(Files.readAllBytes(path)));
        } catch (IOException | IllegalArgumentException error) { showError("Rule import failed", error); }
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
        rules.apply(pack); persistRules.accept(pack); updateRuleInfo(); scanner.restartHistoryScan();
    }

    private void rescan() { scanner.restartHistoryScan(); }
    private void updateRuleInfo() {
        LoadedRulePack p = rules.current(); ruleInfo.setText("Active pack: " + p.version() + " | " + p.rules().size() + " rules | SHA-256 " + p.shortHash() + "…");
    }
    private void updateScanInfo() {
        ScanState s = lastScanState;
        String dropped = droppedFindings > 0 ? " | capped: " + droppedFindings : "";
        scanInfo.setText(s.phase() + " | queued: " + s.queued() + " | active: " + s.inFlight() + " | scanned: " + s.scanned()
                + " | findings: " + s.findings() + " | visible: " + findingTable.getRowCount() + dropped + " | " + s.message());
    }
    private void updateScannerButtons() {
        if (pauseButton != null) pauseButton.setText(lastScanState.phase() == ScanState.Phase.PAUSED ? "Resume" : "Pause");
        if (cancelButton != null) cancelButton.setEnabled(lastScanState.queued() > 0 || lastScanState.inFlight() > 0
                || lastScanState.phase() == ScanState.Phase.SCANNING || lastScanState.phase() == ScanState.Phase.PAUSED);
    }
    private void showError(String title, Throwable error) {
        String message = error == null || error.getMessage() == null || error.getMessage().isBlank()
                ? (error == null ? "Unknown error" : error.getClass().getSimpleName()) : error.getMessage();
        JOptionPane.showMessageDialog(api.userInterface().swingUtils().suiteFrame(), message, title, JOptionPane.ERROR_MESSAGE);
    }
    private static String host(String url) {
        try { String host = java.net.URI.create(url).getHost(); return host == null ? "asset" : host; }
        catch (RuntimeException error) { return "asset"; }
    }
    private static JButton addButton(JPanel panel, String label, Runnable action) {
        JButton button = new JButton(label); button.addActionListener(e -> action.run()); panel.add(button); return button;
    }
    private JButton addSelectionButton(JPanel panel, String label, Runnable action, String tooltip) {
        JButton button = addButton(panel, label, action); button.setToolTipText(tooltip); selectionActions.add(button); return button;
    }

    private static final class FindingModel extends AbstractTableModel {
        private final String[] columns = {"Severity", "Confidence", "Kind", "Rule", "Value", "Line", "Asset URL", "Status", "Published"};
        private List<Finding> rows = new ArrayList<>();
        void replace(List<Finding> values) { rows = new ArrayList<>(values); fireTableDataChanged(); }
        Finding get(int row) { return rows.get(row); }
        public int getRowCount() { return rows.size(); } public int getColumnCount() { return columns.length; }
        public String getColumnName(int column) { return columns[column]; }
        public Object getValueAt(int row, int column) { Finding f = rows.get(row); return switch (column) {
            case 0 -> f.severity(); case 1 -> f.confidence(); case 2 -> f.kind(); case 3 -> f.ruleName();
            case 4 -> f.maskedValue(); case 5 -> f.line(); case 6 -> f.assetUrl(); case 7 -> f.reviewStatus(); default -> f.published() ? "Yes" : ""; }; }
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

    static final class ResponsiveActionPanel extends JPanel {
        private int columns;
        ResponsiveActionPanel() {
            setBorder(BorderFactory.createEmptyBorder(4, 4, 4, 4));
            addComponentListener(new ComponentAdapter() {
                @Override public void componentResized(ComponentEvent e) { updateColumns(); }
            });
            updateColumns();
        }
        private void updateColumns() {
            int width = getWidth();
            int desired = width >= 1100 ? 6 : width >= 760 ? 4 : 3;
            if (desired == columns) return;
            columns = desired; setLayout(new GridLayout(0, columns, 4, 4)); revalidate();
        }
        int columns() { return columns; }
    }

    @FunctionalInterface private interface DocumentChange extends javax.swing.event.DocumentListener {
        void update(javax.swing.event.DocumentEvent event);
        default void insertUpdate(javax.swing.event.DocumentEvent e) { update(e); }
        default void removeUpdate(javax.swing.event.DocumentEvent e) { update(e); }
        default void changedUpdate(javax.swing.event.DocumentEvent e) { update(e); }
    }
}
