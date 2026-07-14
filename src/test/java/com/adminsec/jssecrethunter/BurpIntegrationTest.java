package com.adminsec.jssecrethunter;

import burp.api.montoya.http.message.requests.HttpRequest;
import com.adminsec.jssecrethunter.model.Confidence;
import com.adminsec.jssecrethunter.model.Finding;
import com.adminsec.jssecrethunter.model.FindingKind;
import com.adminsec.jssecrethunter.model.Severity;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;

class BurpIntegrationTest {
    @Test
    void issueDetailIsRedactedAndHtmlEscaped() {
        String raw = "sk-proj-AbCdEfGhIjKlMnOpQrStUvWxYz012345";
        Finding finding = finding(raw, Severity.CRITICAL, Confidence.HIGH);
        String detail = BurpIntegration.detail(finding);
        assertFalse(detail.contains(raw));
        assertTrue(detail.contains(finding.maskedValue()));
        assertTrue(detail.contains("Vendor &lt;token&gt;"));
    }

    @Test
    void mapsCandidateRatingsConservatively() {
        assertEquals("HIGH", BurpIntegration.severity(Severity.CRITICAL).name());
        assertEquals("MEDIUM", BurpIntegration.severity(Severity.MEDIUM).name());
        assertEquals("INFORMATION", BurpIntegration.severity(Severity.INFO).name());
        assertEquals("FIRM", BurpIntegration.confidence(Confidence.HIGH).name());
        assertEquals("TENTATIVE", BurpIntegration.confidence(Confidence.MEDIUM).name());
        assertEquals("TENTATIVE", BurpIntegration.confidence(Confidence.LOW).name());
    }

    private static Finding finding(String raw, Severity severity, Confidence confidence) {
        return new Finding("vendor-token", "Vendor <token>", FindingKind.SECRET, severity, confidence,
                "https://app.test/app.js", "https://app.test/", List.of("https://app.test/", "https://app.test/app.js"),
                7, 10, 10 + raw.length(), "masked evidence", raw, mock(HttpRequest.class), null);
    }
}
