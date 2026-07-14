package com.adminsec.jssecrethunter;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.ui.UserInterface;
import burp.api.montoya.ui.editor.EditorOptions;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.ui.editor.HttpResponseEditor;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.adminsec.jssecrethunter.model.Confidence;
import com.adminsec.jssecrethunter.model.Finding;
import com.adminsec.jssecrethunter.model.FindingKind;
import com.adminsec.jssecrethunter.model.Severity;
import org.junit.jupiter.api.Test;

import javax.swing.JButton;
import javax.swing.JPanel;
import javax.swing.JTabbedPane;
import javax.swing.SwingUtilities;
import java.awt.Component;
import java.awt.Container;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class HunterPanelActionTest {
    @Test
    void allFindingActionsExistAndSelectionActionsStartDisabled() throws Exception {
        MontoyaApi api = mock(MontoyaApi.class);
        UserInterface ui = mock(UserInterface.class);
        HttpRequestEditor requestEditor = mock(HttpRequestEditor.class);
        HttpResponseEditor responseEditor = mock(HttpResponseEditor.class);
        when(api.userInterface()).thenReturn(ui);
        when(ui.createHttpRequestEditor(any(EditorOptions[].class))).thenReturn(requestEditor);
        when(ui.createHttpResponseEditor(any(EditorOptions[].class))).thenReturn(responseEditor);
        when(requestEditor.uiComponent()).thenReturn(new JPanel());
        when(responseEditor.uiComponent()).thenReturn(new JPanel());
        HunterRepository repository = new HunterRepository(null);
        HunterPanel panel = new HunterPanel(api, new HunterConfig(), repository,
                new RulePackManager(), mock(ScannerService.class), ignored -> {});
        List<JButton> buttons = buttons(panel);
        Set<String> labels = buttons.stream().map(JButton::getText).collect(Collectors.toSet());
        Set<String> findingActions = Set.of("Reveal", "Copy value", "Send to Repeater", "Reviewed", "False positive",
                "Needs review", "Ignore rule", "Ignore host", "Add as Burp issue", "Export JSON", "Export CSV", "Export full…");
        assertTrue(labels.containsAll(findingActions));
        assertEquals(12, findingActions.size());
        JTabbedPane tabs = (JTabbedPane) panel.getComponent(0);
        assertTrue(java.util.stream.IntStream.range(0, tabs.getTabCount()).anyMatch(index -> "Links".equals(tabs.getTitleAt(index))));
        for (JButton button : buttons) {
            if (Set.of("Reveal", "Copy value", "Send to Repeater", "Reviewed", "False positive", "Needs review",
                    "Ignore rule", "Ignore host", "Add as Burp issue").contains(button.getText())) assertFalse(button.isEnabled());
        }
        HttpRequest request = mock(HttpRequest.class);
        when(request.url()).thenReturn("https://app.test/app.js");
        repository.addFindings(List.of(new Finding("api-endpoint", "API endpoint", FindingKind.ENDPOINT,
                Severity.INFO, Confidence.HIGH, request.url(), request.url(), List.of(request.url()),
                1, 0, 7, "endpoint", "/api/v1", request, null)));
        long deadline = System.nanoTime() + java.util.concurrent.TimeUnit.SECONDS.toNanos(3);
        while (panel.linkCount() != 1 && System.nanoTime() < deadline) {
            Thread.sleep(20); SwingUtilities.invokeAndWait(() -> {});
        }
        assertEquals(1, panel.linkCount());
    }

    private static List<JButton> buttons(Component root) {
        List<JButton> values = new ArrayList<>();
        if (root instanceof JButton button) values.add(button);
        if (root instanceof Container container) for (Component child : container.getComponents()) values.addAll(buttons(child));
        return values;
    }
}
