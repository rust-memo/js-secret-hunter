package com.adminsec.jssecrethunter;

import org.junit.jupiter.api.Test;

import java.awt.event.ComponentEvent;

import static org.junit.jupiter.api.Assertions.assertEquals;

class HunterPanelLayoutTest {
    @Test
    void actionGridAdaptsWithoutDroppingButtons() {
        HunterPanel.ResponsiveActionPanel panel = new HunterPanel.ResponsiveActionPanel();
        for (int i = 0; i < 12; i++) panel.add(new javax.swing.JButton("Action " + i));
        resize(panel, 650);
        assertEquals(3, panel.columns());
        assertEquals(12, panel.getComponentCount());
        int narrowHeight = panel.getPreferredSize().height;
        resize(panel, 800);
        assertEquals(4, panel.columns());
        resize(panel, 1200);
        assertEquals(6, panel.columns());
        int wideHeight = panel.getPreferredSize().height;
        org.junit.jupiter.api.Assertions.assertTrue(narrowHeight > wideHeight);
    }

    private static void resize(HunterPanel.ResponsiveActionPanel panel, int width) {
        panel.setSize(width, 200);
        panel.dispatchEvent(new ComponentEvent(panel, ComponentEvent.COMPONENT_RESIZED));
    }
}
