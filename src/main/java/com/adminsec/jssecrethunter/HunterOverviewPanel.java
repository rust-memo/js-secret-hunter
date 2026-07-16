package com.adminsec.jssecrethunter;

import com.adminsec.jssecrethunter.model.Finding;
import com.adminsec.jssecrethunter.model.FindingKind;
import com.adminsec.jssecrethunter.model.ReviewStatus;
import com.adminsec.jssecrethunter.model.Severity;

import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JProgressBar;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTable;
import javax.swing.ListSelectionModel;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.DefaultTableCellRenderer;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.FlowLayout;
import java.awt.Font;
import java.awt.GridLayout;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.function.Consumer;

final class HunterOverviewPanel extends JPanel {
    private final JLabel needsReview = valueLabel();
    private final JLabel exposure = valueLabel();
    private final JLabel vulnerable = valueLabel();
    private final JLabel sensitiveFiles = valueLabel();
    private final JLabel attackSurface = valueLabel();
    private final JLabel triageValue = valueLabel();
    private final JLabel scanStatus = new JLabel("Idle");
    private final JProgressBar triageProgress = new JProgressBar(0, 100);
    private final RecentModel recentModel = new RecentModel();
    private final JTable recentTable = new JTable(recentModel);
    private final Consumer<Finding> openFinding;
    private final JButton openButton = new JButton("Review selected");
    private final JButton pauseButton = new JButton("Pause");
    private final JButton cancelButton = new JButton("Cancel queue");

    HunterOverviewPanel(Runnable scan, Runnable pause, Runnable cancel, Runnable clear, Runnable showVulnerabilities,
                        Consumer<Finding> openFinding) {
        super(new BorderLayout(0, 10));
        this.openFinding = openFinding;
        setBorder(BorderFactory.createEmptyBorder(12, 12, 12, 12));
        add(hero(scan, clear), BorderLayout.NORTH);
        add(content(showVulnerabilities), BorderLayout.CENTER);
        openButton.setEnabled(false);
        openButton.addActionListener(ignored -> openSelected());
        pauseButton.addActionListener(ignored -> pause.run());
        cancelButton.addActionListener(ignored -> cancel.run());
    }

    void updateSnapshot(HunterRepository.Snapshot snapshot) {
        OverviewMetrics metrics = OverviewMetrics.from(snapshot);
        needsReview.setText(Integer.toString(metrics.needsReview()));
        exposure.setText(metrics.critical() + " critical · " + metrics.high() + " high");
        vulnerable.setText(Integer.toString(metrics.vulnerabilities()));
        sensitiveFiles.setText(Integer.toString(metrics.sensitiveFiles()));
        attackSurface.setText(Integer.toString(metrics.attackSurface()));
        triageValue.setText(metrics.triagePercent() + "%");
        triageProgress.setValue(metrics.triagePercent());
        recentModel.replace(snapshot.findings());
        openButton.setEnabled(selected() != null);
    }

    void updateState(ScanState state, int dropped) {
        if (state == null) return;
        pauseButton.setText(state.phase() == ScanState.Phase.PAUSED ? "Resume" : "Pause");
        boolean busy = state.queued() > 0 || state.inFlight() > 0
                || state.phase() == ScanState.Phase.SCANNING || state.phase() == ScanState.Phase.PAUSED;
        cancelButton.setEnabled(busy);
        String capped = dropped > 0 ? " · capped " + dropped : "";
        scanStatus.setText(state.phase() + " · queued " + state.queued() + " · active " + state.inFlight()
                + " · scanned " + state.scanned() + " · findings " + state.findings() + capped + " · " + state.message());
    }

    private JPanel hero(Runnable scan, Runnable clear) {
        JPanel hero = new JPanel(new BorderLayout(12, 8));
        JPanel copy = new JPanel(new GridLayout(0, 1, 0, 3));
        JLabel eyebrow = new JLabel("CLIENT-SIDE SECURITY INTELLIGENCE");
        eyebrow.setFont(eyebrow.getFont().deriveFont(Font.BOLD, 11f));
        JLabel title = new JLabel("Find exposed secrets and risky JavaScript before attackers do.");
        title.setFont(title.getFont().deriveFont(Font.BOLD, 18f));
        copy.add(eyebrow); copy.add(title);
        copy.add(new JLabel("Passive local analysis of Proxy History, source maps, application routes, and vulnerability candidates."));
        JPanel actions = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        JButton scanButton = new JButton("Scan History");
        scanButton.addActionListener(ignored -> scan.run());
        JButton clearButton = new JButton("Clear results");
        clearButton.addActionListener(ignored -> clear.run());
        actions.add(scanButton); actions.add(pauseButton); actions.add(cancelButton); actions.add(clearButton);
        hero.add(copy, BorderLayout.CENTER); hero.add(actions, BorderLayout.SOUTH);
        return hero;
    }

    private JPanel content(Runnable showVulnerabilities) {
        JPanel content = new JPanel(new BorderLayout(0, 10));
        JPanel cards = new JPanel(new GridLayout(2, 3, 8, 8));
        cards.add(card("NEEDS REVIEW", needsReview, "Untriaged candidates", new Color(0x4F, 0x8C, 0xFF)));
        cards.add(card("CRITICAL EXPOSURE", exposure, "Prioritize verified secrets", new Color(0xE5, 0x3E, 0x3E)));
        cards.add(card("VULNERABILITY CANDIDATES", vulnerable, "Manual data-flow review required", new Color(0xED, 0x89, 0x36)));
        cards.add(card("SENSITIVE FILES", sensitiveFiles, "Files containing non-endpoint signals", new Color(0x80, 0x5A, 0xD5)));
        cards.add(card("ATTACK SURFACE", attackSurface, "Endpoints and configuration references", new Color(0x38, 0xA1, 0x69)));
        JPanel triageCard = card("TRIAGE COMPLETE", triageValue, "Reviewed or false positive", new Color(0x31, 0x9A, 0xA8));
        triageProgress.setStringPainted(false);
        triageCard.add(triageProgress, BorderLayout.SOUTH);
        cards.add(triageCard);
        content.add(cards, BorderLayout.NORTH);

        configureRecentTable();
        JPanel recent = new JPanel(new BorderLayout(0, 6));
        JPanel recentHeading = new JPanel(new BorderLayout());
        JLabel heading = new JLabel("Latest signals");
        heading.setFont(heading.getFont().deriveFont(Font.BOLD, 14f));
        recentHeading.add(heading, BorderLayout.WEST); recentHeading.add(openButton, BorderLayout.EAST);
        recent.add(recentHeading, BorderLayout.NORTH); recent.add(new JScrollPane(recentTable), BorderLayout.CENTER);

        JPanel safety = new JPanel(new BorderLayout(0, 8));
        safety.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createMatteBorder(1, 4, 1, 1, new Color(0x38, 0xA1, 0x69)),
                BorderFactory.createEmptyBorder(12, 12, 12, 12)));
        JLabel safetyTitle = new JLabel("Safe collection controls");
        safetyTitle.setFont(safetyTitle.getFont().deriveFont(Font.BOLD, 14f));
        safety.add(safetyTitle, BorderLayout.NORTH);
        safety.add(new JLabel("<html>History analysis is local. Automatic asset requests and every redirect remain restricted "
                + "to Burp Target Scope. Raw values stay masked until you explicitly reveal or export them.</html>"), BorderLayout.CENTER);
        JPanel safetyActions = new JPanel(new BorderLayout(6, 6));
        JButton vulnerabilityQueue = new JButton("Open vulnerability queue");
        vulnerabilityQueue.addActionListener(ignored -> showVulnerabilities.run());
        JPanel buttonRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 0, 0));
        buttonRow.add(vulnerabilityQueue);
        scanStatus.setBorder(BorderFactory.createEmptyBorder(8, 0, 0, 0));
        safetyActions.add(buttonRow, BorderLayout.NORTH); safetyActions.add(scanStatus, BorderLayout.SOUTH);
        safety.add(safetyActions, BorderLayout.SOUTH);

        JSplitPane lower = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, recent, safety);
        lower.setResizeWeight(.72); lower.setBorder(null);
        content.add(lower, BorderLayout.CENTER);
        return content;
    }

    private void configureRecentTable() {
        recentTable.setFillsViewportHeight(true);
        recentTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        recentTable.setRowHeight(Math.max(24, recentTable.getRowHeight()));
        recentTable.setDefaultRenderer(Severity.class, new SeverityRenderer());
        int[] widths = {75, 210, 420, 105};
        for (int index = 0; index < widths.length; index++) {
            recentTable.getColumnModel().getColumn(index).setPreferredWidth(widths[index]);
        }
        recentTable.getSelectionModel().addListSelectionListener(ignored -> openButton.setEnabled(selected() != null));
        recentTable.addMouseListener(new MouseAdapter() {
            @Override public void mouseClicked(MouseEvent event) { if (event.getClickCount() == 2) openSelected(); }
        });
    }

    private static JPanel card(String title, JLabel value, String subtitle, Color accent) {
        JPanel card = new JPanel(new BorderLayout(4, 4));
        card.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createMatteBorder(1, 4, 1, 1, accent),
                BorderFactory.createEmptyBorder(9, 11, 9, 11)));
        JLabel heading = new JLabel(title);
        heading.setFont(heading.getFont().deriveFont(Font.BOLD, 10f));
        card.add(heading, BorderLayout.NORTH); card.add(value, BorderLayout.CENTER);
        card.add(new JLabel(subtitle), BorderLayout.SOUTH);
        return card;
    }

    private static JLabel valueLabel() {
        JLabel label = new JLabel("0");
        label.setFont(label.getFont().deriveFont(Font.BOLD, 19f));
        return label;
    }

    private Finding selected() {
        int row = recentTable.getSelectedRow();
        return row < 0 ? null : recentModel.get(recentTable.convertRowIndexToModel(row));
    }

    private void openSelected() {
        Finding finding = selected();
        if (finding != null) openFinding.accept(finding);
    }

    record OverviewMetrics(int total, int needsReview, int critical, int high, int vulnerabilities,
                           int sensitiveFiles, int attackSurface, int assets, int triagePercent) {
        static OverviewMetrics from(HunterRepository.Snapshot snapshot) {
            int total = snapshot.findings().size(), needsReview = 0, critical = 0, high = 0;
            int vulnerabilities = 0, attackSurface = 0, triaged = 0;
            Set<String> files = new HashSet<>();
            for (Finding finding : snapshot.findings()) {
                if (finding.reviewStatus() == ReviewStatus.NEEDS_REVIEW) needsReview++;
                else triaged++;
                if (finding.severity() == Severity.CRITICAL) critical++;
                if (finding.severity() == Severity.HIGH) high++;
                if (finding.kind() == FindingKind.VULNERABILITY) vulnerabilities++;
                if (finding.kind() == FindingKind.ENDPOINT || finding.kind() == FindingKind.CONFIGURATION) attackSurface++;
                if (finding.kind() != FindingKind.ENDPOINT) files.add(finding.assetUrl());
            }
            int percent = total == 0 ? 100 : (int) Math.round((double) triaged * 100 / total);
            return new OverviewMetrics(total, needsReview, critical, high, vulnerabilities,
                    files.size(), attackSurface, snapshot.assets().size(), percent);
        }
    }

    private static final class RecentModel extends AbstractTableModel {
        private static final String[] COLUMNS = {"Severity", "Signal", "Asset", "Status"};
        private List<Finding> rows = new ArrayList<>();
        void replace(List<Finding> values) {
            rows = values.stream().sorted(Comparator.comparing(Finding::discoveredAt).reversed()).limit(12).toList();
            fireTableDataChanged();
        }
        Finding get(int row) { return rows.get(row); }
        public int getRowCount() { return rows.size(); }
        public int getColumnCount() { return COLUMNS.length; }
        public String getColumnName(int column) { return COLUMNS[column]; }
        public Class<?> getColumnClass(int column) { return column == 0 ? Severity.class
                : column == 3 ? ReviewStatus.class : String.class; }
        public Object getValueAt(int row, int column) {
            Finding finding = rows.get(row);
            return switch (column) {
                case 0 -> finding.severity(); case 1 -> finding.ruleName();
                case 2 -> Finding.redactUrlValue(finding.assetUrl()); default -> finding.reviewStatus();
            };
        }
    }

    private static final class SeverityRenderer extends DefaultTableCellRenderer {
        @Override public Component getTableCellRendererComponent(JTable table, Object value, boolean selected,
                                                                  boolean focused, int row, int column) {
            Component component = super.getTableCellRendererComponent(table, value, selected, focused, row, column);
            component.setFont(component.getFont().deriveFont(value instanceof Severity ? Font.BOLD : Font.PLAIN));
            if (!selected && value instanceof Severity severity) {
                boolean dark = table.getBackground().getRed() + table.getBackground().getGreen()
                        + table.getBackground().getBlue() < 384;
                component.setForeground(switch (severity) {
                    case CRITICAL -> dark ? new Color(255, 120, 120) : new Color(183, 28, 28);
                    case HIGH -> dark ? new Color(255, 183, 77) : new Color(230, 81, 0);
                    case MEDIUM -> dark ? new Color(255, 213, 79) : new Color(130, 92, 0);
                    case INFO -> table.getForeground();
                });
            }
            return component;
        }
    }
}
