package com.adminsec.jssecrethunter;

import burp.api.montoya.http.message.requests.HttpRequest;
import com.adminsec.jssecrethunter.model.*;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.mock;

class HunterExporterTest {
    @Test
    void redactedExportDoesNotContainRawCredential() {
        String raw = "sk-proj-AbCdEfGhIjKlMnOpQrStUvWxYz";
        Finding finding = new Finding("openai", "OpenAI", FindingKind.SECRET, Severity.CRITICAL, Confidence.HIGH,
                "https://app.test/a.js", "https://app.test/", List.of("https://app.test/", "https://app.test/a.js"),
                1, 0, raw.length(), "masked", raw, mock(HttpRequest.class), null);
        assertFalse(HunterExporter.json(List.of(finding), false).contains(raw));
        assertFalse(HunterExporter.csv(List.of(finding), false).contains(raw));
        assertTrue(HunterExporter.json(List.of(finding), true).contains(raw));
    }

    @Test
    void csvProtectsSpreadsheetFormulaCells() {
        Finding finding = new Finding("endpoint", "Endpoint", FindingKind.ENDPOINT, Severity.INFO, Confidence.HIGH,
                "=HYPERLINK(\"https://example.test\")", "https://app.test/", List.of(),
                1, 0, 1, "preview", "/api", mock(HttpRequest.class), null);
        assertTrue(HunterExporter.csv(List.of(finding), false).contains("\"'=HYPERLINK"));
    }
}
