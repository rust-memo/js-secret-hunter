package com.adminsec.jssecrethunter;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.ui.UserInterface;
import burp.api.montoya.ui.editor.EditorOptions;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.ui.editor.HttpResponseEditor;
import org.junit.jupiter.api.Test;

import javax.swing.JButton;
import javax.swing.JPanel;
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
    void allFindingActionsExistAndSelectionActionsStartDisabled() {
        MontoyaApi api = mock(MontoyaApi.class);
        UserInterface ui = mock(UserInterface.class);
        HttpRequestEditor requestEditor = mock(HttpRequestEditor.class);
        HttpResponseEditor responseEditor = mock(HttpResponseEditor.class);
        when(api.userInterface()).thenReturn(ui);
        when(ui.createHttpRequestEditor(any(EditorOptions[].class))).thenReturn(requestEditor);
        when(ui.createHttpResponseEditor(any(EditorOptions[].class))).thenReturn(responseEditor);
        when(requestEditor.uiComponent()).thenReturn(new JPanel());
        when(responseEditor.uiComponent()).thenReturn(new JPanel());
        HunterPanel panel = new HunterPanel(api, new HunterConfig(), new HunterRepository(null),
                new RulePackManager(), mock(ScannerService.class), ignored -> {});
        List<JButton> buttons = buttons(panel);
        Set<String> labels = buttons.stream().map(JButton::getText).collect(Collectors.toSet());
        Set<String> findingActions = Set.of("Reveal", "Copy value", "Send to Repeater", "Reviewed", "False positive",
                "Needs review", "Ignore rule", "Ignore host", "Add as Burp issue", "Export JSON", "Export CSV", "Export full…");
        assertTrue(labels.containsAll(findingActions));
        assertEquals(12, findingActions.size());
        for (JButton button : buttons) {
            if (Set.of("Reveal", "Copy value", "Send to Repeater", "Reviewed", "False positive", "Needs review",
                    "Ignore rule", "Ignore host", "Add as Burp issue").contains(button.getText())) assertFalse(button.isEnabled());
        }
    }

    private static List<JButton> buttons(Component root) {
        List<JButton> values = new ArrayList<>();
        if (root instanceof JButton button) values.add(button);
        if (root instanceof Container container) for (Component child : container.getComponents()) values.addAll(buttons(child));
        return values;
    }
}
