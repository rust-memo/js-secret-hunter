package com.adminsec.jssecrethunter;

import burp.api.montoya.http.message.requests.HttpRequest;
import com.adminsec.jssecrethunter.model.AssetRecord;
import com.adminsec.jssecrethunter.model.Confidence;
import com.adminsec.jssecrethunter.model.Finding;
import com.adminsec.jssecrethunter.model.FindingKind;
import com.adminsec.jssecrethunter.model.ReviewStatus;
import com.adminsec.jssecrethunter.model.Severity;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.mock;

class HunterOverviewPanelTest {
    @Test
    void summarizesRiskAndTriageLikeTheDashboard() {
        Finding secret = finding("secret", FindingKind.SECRET, Severity.CRITICAL, "https://app.test/app.js");
        Finding vulnerability = finding("dom-xss", FindingKind.VULNERABILITY, Severity.HIGH, "https://app.test/app.js");
        vulnerability.reviewStatus(ReviewStatus.REVIEWED);
        Finding endpoint = finding("endpoint", FindingKind.ENDPOINT, Severity.INFO, "https://app.test/app.js");
        endpoint.reviewStatus(ReviewStatus.FALSE_POSITIVE);
        HunterRepository.Snapshot snapshot = new HunterRepository.Snapshot(List.of(secret, vulnerability, endpoint),
                List.of(mock(AssetRecord.class)), 0);

        HunterOverviewPanel.OverviewMetrics metrics = HunterOverviewPanel.OverviewMetrics.from(snapshot);
        assertEquals(3, metrics.total());
        assertEquals(1, metrics.needsReview());
        assertEquals(1, metrics.critical());
        assertEquals(1, metrics.high());
        assertEquals(1, metrics.vulnerabilities());
        assertEquals(1, metrics.sensitiveFiles());
        assertEquals(1, metrics.attackSurface());
        assertEquals(67, metrics.triagePercent());
    }

    private static Finding finding(String id, FindingKind kind, Severity severity, String url) {
        return new Finding(id, id, kind, severity, Confidence.MEDIUM, url, url, List.of(url),
                1, 0, 4, "preview", "value", mock(HttpRequest.class), null);
    }
}
